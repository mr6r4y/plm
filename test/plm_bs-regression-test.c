#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/*
 * The queue pointer-lifetime test needs realloc() to move deterministically.
 * Keep the old allocation alive and poison it so the test can inspect the
 * stale slice without itself performing a use-after-free.
 */
static void *tracked_allocation;
static size_t tracked_size;
static void *retired_allocation;
static bool force_realloc_move;
static bool fail_realloc;
static bool invalid_memcpy_call;

static void *raw_memcpy(void *dst, const void *src, size_t size)
{
	return memcpy(dst, src, size);
}

static void allocator_reset(void)
{
	if (tracked_allocation)
		free(tracked_allocation);
	if (retired_allocation)
		free(retired_allocation);
	tracked_allocation = NULL;
	tracked_size = 0;
	retired_allocation = NULL;
	force_realloc_move = false;
	fail_realloc = false;
	invalid_memcpy_call = false;
}

static void *plm_test_malloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr) {
		tracked_allocation = ptr;
		tracked_size = size;
	}
	return ptr;
}

static void plm_test_free(void *ptr)
{
	if (ptr == tracked_allocation) {
		free(ptr);
		tracked_allocation = NULL;
		tracked_size = 0;
		return;
	}
	if (ptr == retired_allocation) {
		free(ptr);
		retired_allocation = NULL;
		return;
	}
	free(ptr);
}

static void *plm_test_realloc(void *ptr, size_t size)
{
	void *new_ptr;
	size_t copy_size;

	if (fail_realloc || ptr != tracked_allocation)
		return NULL;

	if (!force_realloc_move) {
		new_ptr = realloc(ptr, size);
		if (new_ptr) {
			tracked_allocation = new_ptr;
			tracked_size = size;
		}
		return new_ptr;
	}

	new_ptr = malloc(size);
	if (!new_ptr)
		return NULL;

	copy_size = tracked_size < size ? tracked_size : size;
	raw_memcpy(new_ptr, ptr, copy_size);
	memset(ptr, 0xa5, tracked_size);
	retired_allocation = ptr;
	tracked_allocation = new_ptr;
	tracked_size = size;
	return new_ptr;
}

static void *plm_test_memcpy(void *dst, const void *src, size_t size)
{
	if (size != 0 && (!dst || !src)) {
		invalid_memcpy_call = true;
		return dst;
	}
	return raw_memcpy(dst, src, size);
}

#define plm_malloc(size) plm_test_malloc(size)
#define plm_free(ptr) plm_test_free(ptr)
#define plm_realloc(ptr, size) plm_test_realloc((ptr), (size))
#define memcpy(dst, src, size) plm_test_memcpy((dst), (src), (size))
#define PLM_BS_IMPLEMENTATION
#include "plm_bs.h"
#undef memcpy

static void reset_fatal_signal_handlers(void)
{
	(void)signal(SIGABRT, SIG_DFL);
	(void)signal(SIGFPE, SIG_DFL);
	(void)signal(SIGILL, SIG_DFL);
	(void)signal(SIGSEGV, SIG_DFL);
#ifdef SIGBUS
	(void)signal(SIGBUS, SIG_DFL);
#endif
#ifdef SIGSYS
	(void)signal(SIGSYS, SIG_DFL);
#endif
}

static bool child_succeeded(int (*callback)(void))
{
	pid_t child;
	pid_t waited;
	int status;

	child = fork();
	assert_true(child >= 0);
	if (child == 0) {
		reset_fatal_signal_handlers();
		_exit(callback());
	}

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);

	return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int stralloc_exhaustion_child(void)
{
	Vmem vm;
	char *result;

	if (!vmem_create(&vm, 16))
		return 1;
	result = vmem_stralloc(&vm, "too long for arena");
	vmem_destroy(&vm);
	return result == NULL ? 0 : 2;
}

static int mock_realloc_shrink_child(void)
{
	Vmem vm;
	void *ptr;
	void *result;
	bool returned_original;

	if (!vmem_create(&vm, 128))
		return 1;
	ptr = vmem_alloc(&vm, 16);
	if (!ptr) {
		vmem_destroy(&vm);
		return 2;
	}
	result = plm_mock_realloc(&vm, ptr, 8);
	returned_original = result == ptr;
	vmem_destroy(&vm);
	return returned_original ? 0 : 3;
}

static void plm_bs_test_stralloc_exhaustion(void **state)
{
	(void)state;
	allocator_reset();
	assert_true(child_succeeded(stralloc_exhaustion_child));
	allocator_reset();
}

static void plm_bs_test_queue_slice_survives_growth(void **state)
{
	PlmQueue queue;
	PlmSlice slice;
	char large_value[32] = { 0 };
	bool preserved;

	(void)state;
	allocator_reset();
	assert_true(plm_queue_create(&queue, 64));
	assert_true(plm_queue_put(&queue, "abc", 4));
	slice = plm_queue_get(&queue);

	force_realloc_move = true;
	assert_true(plm_queue_put(&queue, large_value, sizeof(large_value)));
	preserved = slice.size == 4 && memcmp(slice.ptr, "abc", 4) == 0;

	plm_queue_destroy(&queue);
	allocator_reset();
	assert_true(preserved);
}

static void plm_bs_test_alloc_rejects_size_overflow(void **state)
{
	Vmem vm;
	void *result;
	size_t old_end;
	size_t old_len;
	bool rejected;

	(void)state;
	allocator_reset();
	assert_true(vmem_create(&vm, 256));
	old_end = vm.end;
	old_len = vm.len;

	result = vmem_alloc(&vm, SIZE_MAX - sizeof(VChunkHdr) + 1);
	rejected = result == NULL && vm.end == old_end && vm.len == old_len;

	vmem_destroy(&vm);
	allocator_reset();
	assert_true(rejected);
}

static void plm_bs_test_grow_rejects_size_overflow(void **state)
{
	Vmem vm;
	size_t old_alloc;
	bool result;
	bool rejected;

	(void)state;
	allocator_reset();
	assert_true(vmem_create(&vm, 64));
	vm.can_grow = true;
	old_alloc = vm.alloc;

	result = vmem_grow(&vm, SIZE_MAX - old_alloc + 33);
	rejected = !result && vm.alloc == old_alloc;

	vmem_destroy(&vm);
	allocator_reset();
	assert_true(rejected);
}

static void plm_bs_test_mock_realloc_handles_oom(void **state)
{
	Vmem vm;
	void *ptr;
	void *result;
	bool copied_to_null;

	(void)state;
	allocator_reset();
	assert_true(vmem_create(&vm, 64));
	ptr = vmem_alloc(&vm, 8);
	assert_non_null(ptr);

	result = plm_mock_realloc(&vm, ptr, 128);
	copied_to_null = invalid_memcpy_call;

	vmem_destroy(&vm);
	allocator_reset();
	assert_null(result);
	assert_false(copied_to_null);
}

static void plm_bs_test_mock_realloc_shrink_returns_original(void **state)
{
	(void)state;
	allocator_reset();
	assert_true(child_succeeded(mock_realloc_shrink_child));
	allocator_reset();
}

static void plm_bs_test_alloc_returns_max_aligned_storage(void **state)
{
	Vmem vm;
	void *result;
	bool aligned;

	(void)state;
	allocator_reset();
	assert_true(vmem_create(&vm, 256));
	assert_non_null(vmem_alloc(&vm, 1));
	result = vmem_alloc(&vm, sizeof(max_align_t));
	assert_non_null(result);
	aligned = ((uintptr_t)result % _Alignof(max_align_t)) == 0;

	vmem_destroy(&vm);
	allocator_reset();
	assert_true(aligned);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(plm_bs_test_stralloc_exhaustion),
		cmocka_unit_test(plm_bs_test_queue_slice_survives_growth),
		cmocka_unit_test(plm_bs_test_alloc_rejects_size_overflow),
		cmocka_unit_test(plm_bs_test_grow_rejects_size_overflow),
		cmocka_unit_test(plm_bs_test_mock_realloc_handles_oom),
		cmocka_unit_test(plm_bs_test_mock_realloc_shrink_returns_original),
		cmocka_unit_test(plm_bs_test_alloc_returns_max_aligned_storage),
	};

	if (argc > 1)
		cmocka_set_test_filter(argv[1]);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
