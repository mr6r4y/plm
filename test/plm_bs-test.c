#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define PLM_BS_IMPLEMENTATION
#include "plm_bs.h"

#ifndef PLM_BS_TEST_VERBOSE
# define PLM_BS_TEST_VERBOSE 0
#endif

static void print_chunk(VChunkHdr *chunk, size_t ind, void *context)
{
#if PLM_VMEM_CANARY
	assert_true(chunk->canary == PLM_VMEM_CANARY_VALUE);
#endif
#if PLM_BS_TEST_VERBOSE
	printf("Chunk %lu: ch->len = %lu; ch->data = %p\n", ind, chunk->len, chunk->data);
#endif
}

static void plm_bs_test_vmem()
{
	Vmem vm;
	VChunkHdr *chunk;
	char *p;
	size_t l, i, ind;
	char stamp[] = "Iterator test string XXX";

	if (!vmem_create(&vm, 0x3000))
		fail_msg("Error: Can't do vmem_create");

	printf("Simple alloction\n");
	p = vmem_alloc(&vm, 0x120);
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx %p\n\n", l, p);
	assert_true(l == 0x120);

	printf("Simple string allocation\n");
	p = vmem_stralloc(&vm, "Test string 1 !");
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx; p = '%s' %p\n\n", l, p, p);
	assert_true(l == 16);

	printf("Allocate a lot of strings\n");
	for (i = 0; i < 60; i++) {
		stamp[21] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
#if PLM_BS_TEST_VERBOSE
		printf("%lu '%s' %p, strcmp(p, stamp)=%d\n", i, p, p, strcmp(p, stamp));
		printf("%s == %s\n", p, stamp);
#endif
		assert_true(strcmp(p, stamp) == 0);
	}
	for (i = 0; i < 60; i++) {
		stamp[22] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		assert_true(strcmp(p, stamp) == 0);
#if PLM_BS_TEST_VERBOSE
		printf("%lu '%s' %p\n", i, p, p);
#endif
	}
	for (i = 0; i < 60; i++) {
		stamp[23] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		assert_true(strcmp(p, stamp) == 0);
#if PLM_BS_TEST_VERBOSE
		printf("%lu '%s' %p\n", i, p, p);
#endif
	}
	printf("\n");

	ind = 36;
	printf("Get chunk by index 0x%lx\n", ind);
	chunk = vmem_chunk_get_by_index(&vm, ind);
#if PLM_VMEM_CANARY
	printf("chunk->len = 0x%lx; chunk->canary = 0x%lx; chunk->data = '%s' %p\n\n", chunk->len, chunk->canary, (char *)chunk->data, chunk);
#else
	printf("chunk->len = 0x%lx; chunk->data = '%s' %p\n\n", chunk->len, (char *)chunk->data, chunk);
#endif
	printf("\nCurrent vmem state:\n");
	printf("vmem->len = 0x%lx; vmem->alloc = 0x%lx; vmem->end = 0x%lx; vmem->ptr = %p\n", vm.len, vm.alloc, vm.end, vm.ptr);

	printf("\nTest chunk iterator:\n");
	if (!vmem_chunk_iter(&vm, print_chunk, NULL))
		printf("Error: Canary check failed\n");

	printf("\n\nDeallocate everything\n\n");
	vmem_destroy(&vm);
}

static void plm_bs_test_mock_alloc_with_stb_ds()
{
	/* TO-DO: Implement the hash table test with global arena and measure the arena usage */
}

static void plm_bs_test_queue()
{
	PlmQueue q;
	PlmSlice s;
	char stamp[] = "Iterator test string XXX";
#define STAMP_LENGTH 28
	char stamp2[STAMP_LENGTH] = { '\0' };
	size_t l, i, ind;

	printf("Create queue\n");
	if (!plm_queue_create(&q, 0x100))
		fail_msg("Error: Can't create queue");
	printf("\n");

	printf("Iterative put\n");
	for (i = 0; i < 0x1000; i++) {
#if PLM_BS_TEST_VERBOSE
		printf("i=0x%lx;", i);
#endif
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		assert_true(plm_queue_put(&q, stamp2, STAMP_LENGTH));
	}
	printf("\n");

	printf("Iterative get\n");
	for (i = 0; i < 0x1000; i++) {
#if PLM_BS_TEST_VERBOSE
		printf("i=0x%lx;", i);
#endif
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		s = plm_queue_get(&q);
		assert_true(s.size == STAMP_LENGTH);
		assert_true(strcmp(s.ptr, stamp2) == 0);
	}
	printf("\n");

	printf("Check empty\n");
	assert_true(plm_queue_is_empty(&q));
	printf("\n");

	printf("Another put and get\n");
	assert_true(plm_queue_put(&q, "aaaa", 5));
	s = plm_queue_get(&q);
	assert_true(s.size == 5);
	assert_true(strcmp(s.ptr, "aaaa") == 0);
	printf("\n");

	printf("Clear queue\n");
	if (!plm_queue_clear(&q)) {
		printf("Error: Can't clear queue");
		assert_true(false);
	}
	printf("\n");

	printf("Iterative put\n");
	for (i = 0; i < 0x1000; i++) {
#if PLM_BS_TEST_VERBOSE
		printf("i=0x%lx;", i);
#endif
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		assert_true(plm_queue_put(&q, stamp2, STAMP_LENGTH));
	}
	printf("\n");

	printf("Iterative get\n");
	for (i = 0; i < 0x1000; i++) {
#if PLM_BS_TEST_VERBOSE
		printf("i=0x%lx;", i);
#endif
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		s = plm_queue_get(&q);
		assert_true(s.size == STAMP_LENGTH);
		assert_true(strcmp(s.ptr, stamp2) == 0);
	}
	printf("\n");

	printf("Check empty\n");
	assert_true(plm_queue_is_empty(&q));
	printf("\n");

	printf("Another put and get\n");
	assert_true(plm_queue_put(&q, "aaaa", 5));
	s = plm_queue_get(&q);
	assert_true(s.size == 5);
	assert_true(strcmp(s.ptr, "aaaa") == 0);
	printf("\n");

	printf("Destroy queue\n");
	plm_queue_destroy(&q);
	assert_true(q.vm.ptr == NULL);
	printf("\n");
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(plm_bs_test_vmem),
		cmocka_unit_test(plm_bs_test_queue),
	};

	if (argc > 1)
		cmocka_set_test_filter(argv[1]);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
