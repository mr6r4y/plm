/* plm_bs.h - v0.1 - basic data structures and memory allocation primitives - plm 2025
 */

#ifndef PLM_BS_H
#define PLM_BS_H

#define PLM_BS_VERSION "0.2.0"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef PLM_BS_IMPLEMENTATION
# ifndef plm_malloc
#  include <stdlib.h>
#  define plm_malloc(x) malloc(x)
# endif
# ifndef plm_free
#  include <stdlib.h>
#  define plm_free(x) free(x)
# endif
# ifndef plm_realloc
#  include <stdlib.h>
#  define plm_realloc(x, y) realloc((x), (y))
# endif
#endif

#ifndef PLM_VMEM_CANARY
# define PLM_VMEM_CANARY 1
#endif

#ifndef PLM_VMEM_CANARY_VALUE
# define PLM_VMEM_CANARY_VALUE 0xdeadbeefcafecafe
#endif

typedef struct {
	size_t len;
	bool can_grow;
	size_t alloc;
	size_t end;
	void *ptr;

} Vmem;

typedef struct {
	size_t len;
#if PLM_VMEM_CANARY
	u_int64_t canary;
#endif
	char data[];
} VChunkHdr;

typedef void (*VmemChunkIterCallback)(VChunkHdr *chunk, size_t ind, void *context);

extern bool vmem_create(Vmem *vmem, size_t size);
extern bool vmem_grow(Vmem *vmem, size_t size);
extern void *vmem_alloc(Vmem *vmem, size_t size);
extern char *vmem_stralloc(Vmem *vmem, const char *s);
extern size_t vmem_chunk_size_get(void *ptr);
extern size_t vmem_free_size_get(Vmem *vmem);
extern VChunkHdr *vmem_chunk_get_by_index(Vmem *vmem, size_t ind);
extern bool vmem_chunk_iter(Vmem *vmem, VmemChunkIterCallback clb, void *context);
extern void vmem_clear(Vmem *vmem);
extern void vmem_destroy(Vmem *vmem);

extern void *plm_mock_malloc(Vmem *vm, size_t size);
extern void plm_mock_free(Vmem *vm, void *ptr);
extern void *plm_mock_realloc(Vmem *vm, void *ptr, size_t size);

typedef ptrdiff_t QHandle;
#define NULL_HANDLE -1

typedef struct {
	Vmem vm;
	size_t init_size;
	size_t count;
	QHandle first;
	QHandle last;
} PlmQueue;

typedef struct {
	size_t size;
	QHandle prev;
	QHandle next;
	char data[];
} PlmQueueElem;

typedef struct {
	size_t size;
	void *ptr;
} PlmSlice;

extern bool plm_queue_create(PlmQueue *q, size_t size);
QHandle plm_queue_get_handle_by_elem(PlmQueue *q, PlmQueueElem *e);
PlmQueueElem *plm_queue_get_elem_by_handle(PlmQueue *q, QHandle h);
extern bool plm_queue_put(PlmQueue *q, void *data, size_t size);
extern PlmSlice plm_queue_get(PlmQueue *q);
extern bool plm_queue_clear(PlmQueue *q);
extern void plm_queue_destroy(PlmQueue *q);
extern bool plm_queue_is_empty(PlmQueue *q);

#endif /* PLM_BS_H */

#ifdef PLM_BS_IMPLEMENTATION

#include <string.h>

bool vmem_create(Vmem *vmem, size_t size)
{
	size_t alloc, min_size;

	if (size < 1)
		return false;

	vmem->ptr = plm_malloc(size);

	if (!vmem->ptr)
		return false;

	vmem->len = 0;
	vmem->can_grow = false;
	vmem->alloc = size;
	vmem->end = 0;

	return true;
}

bool vmem_grow(Vmem *vmem, size_t size)
{
	void *new_ptr;
	if (!vmem->can_grow)
		return false;
	new_ptr = plm_realloc(vmem->ptr, vmem->alloc + size);
	if (!new_ptr)
		return false;
	vmem->ptr = new_ptr;
	vmem->alloc += size;
	return true;
}

size_t vmem_chunk_size(VChunkHdr *chunk)
{
	size_t align, ch_size;

	align = sizeof(size_t);
	ch_size = sizeof(VChunkHdr) + chunk->len;
	ch_size = ch_size + align - (ch_size & (align - 1));
	return ch_size;
}

size_t vmem_free_size_get(Vmem *vmem)
{
	return vmem->alloc - vmem->end;
}

void *vmem_alloc(Vmem *vmem, size_t size)
{
	size_t align, free, ch_size, extra_alloc;
	VChunkHdr *chunk;

	free = vmem->alloc - vmem->end;
	align = sizeof(size_t);
	ch_size = sizeof(VChunkHdr) + size;
	ch_size = ch_size + align - (ch_size & (align - 1));

	if (free < ch_size) {
		/* If the API returns a pointer the vmem->ptr should be stable. */
		return NULL;
	}

	chunk = (VChunkHdr *)((uintptr_t)(vmem->ptr) + (uintptr_t)vmem->end);
	chunk->len = size;
#if PLM_VMEM_CANARY
	chunk->canary = PLM_VMEM_CANARY_VALUE;
#endif

	vmem->end += ch_size;
	vmem->len += 1;

	return &chunk->data;
}

char *vmem_stralloc(Vmem *vmem, const char *s)
{
	size_t l;
	char *p;
	l = strlen(s);
	p = vmem_alloc(vmem, l + 1);
	if (!p)
		return NULL;
	strncpy(p, s, l);
	return p;
}

size_t vmem_chunk_size_get(void *ptr)
{
	VChunkHdr *chunk;
	chunk = &((VChunkHdr *)ptr)[-1];
#if PLM_VMEM_CANARY
	if (chunk->canary != PLM_VMEM_CANARY_VALUE)
		return 0;
#endif
	return chunk->len;
}

VChunkHdr *vmem_chunk_get_by_index(Vmem *vmem, size_t ind)
{
	VChunkHdr *ch;
	size_t i = 0;
	size_t ch_size;

	if (ind >= vmem->len)
		return NULL;

	ch = (VChunkHdr *)vmem->ptr;
	while (ind != i) {
#if PLM_VMEM_CANARY
		if (ch->canary != PLM_VMEM_CANARY_VALUE)
			return NULL;
#endif
		ch_size = vmem_chunk_size(ch);
		ch = (VChunkHdr *)((uintptr_t)ch + ch_size);

		i++;
	}

	return ch;
}

bool vmem_chunk_iter(Vmem *vmem, VmemChunkIterCallback clb, void *context)
{
	VChunkHdr *ch;
	size_t i = 0;
	size_t ch_size;

	ch = (VChunkHdr *)vmem->ptr;
	for (i = 0; i < vmem->len; i++) {
#if PLM_VMEM_CANARY
		if (ch->canary != PLM_VMEM_CANARY_VALUE)
			return false;
#endif

		clb(ch, i, context);
		ch_size = vmem_chunk_size(ch);
		ch = (VChunkHdr *)((uintptr_t)ch + ch_size);
	}
	return true;
}

void vmem_clear(Vmem *vmem)
{
	vmem->len = 0;
	vmem->end = 0;
}

void vmem_destroy(Vmem *vmem)
{
	vmem->alloc = 0;
	vmem->len = 0;
	vmem->end = 0;
	plm_free(vmem->ptr);
	vmem->ptr = NULL;
}

void *plm_mock_malloc(Vmem *vm, size_t size)
{
	return vmem_alloc(vm, size);
}

void plm_mock_free(Vmem *vm, void *ptr)
{
}

void *plm_mock_realloc(Vmem *vm, void *ptr, size_t size)
{
	size_t s;
	void *new_ptr;
	s = vmem_chunk_size_get(ptr);
	if (s < size) {
		new_ptr = vmem_alloc(vm, size);
		memcpy(new_ptr, ptr, s);
	}

	return new_ptr;
}

bool plm_queue_create(PlmQueue *q, size_t size)
{
	if (!vmem_create(&q->vm, size))
		return false;
	q->vm.can_grow = true;
	q->init_size = size;
	q->count = 0;
	q->first = NULL_HANDLE;
	q->last = NULL_HANDLE;
	return true;
}

PlmQueueElem *plm_queue_get_elem_by_handle(PlmQueue *q, QHandle h)
{
	return (PlmQueueElem *)((uintptr_t)q->vm.ptr + h);
}

QHandle plm_queue_get_handle_by_elem(PlmQueue *q, PlmQueueElem *e)
{
	return (void *)e - q->vm.ptr;
}

size_t plm_queue_vmem_size_for_data(size_t size)
{
	return sizeof(size_t) + sizeof(VChunkHdr) + sizeof(PlmQueueElem) + size;
}

bool plm_queue_put(PlmQueue *q, void *data, size_t size)
{
	PlmQueueElem *e, *p;
	size_t free;
	QHandle h;

	free = vmem_free_size_get(&q->vm);
	if (free < plm_queue_vmem_size_for_data(size)) {
		if (!vmem_grow(&q->vm, q->vm.alloc))
			return false;
	}

	e = (PlmQueueElem *)vmem_alloc(&q->vm, sizeof(PlmQueueElem) + size);
	if (!e)
		return false;
	e->size = size;
	e->prev = q->last;
	e->next = NULL_HANDLE;

	h = plm_queue_get_handle_by_elem(q, e);
	if (q->count == 0)
		q->first = h;
	if (e->prev != NULL_HANDLE) {
		p = plm_queue_get_elem_by_handle(q, e->prev);
		p->next = h;
	}
	q->last = h;

	q->count++;

	memcpy(&e->data, data, size);

	return true;
}

PlmSlice plm_queue_get(PlmQueue *q)
{
	PlmQueueElem *e, *p;
	PlmSlice s;

	if (plm_queue_is_empty(q) || (q->first == NULL_HANDLE)) {
		s.size = 0;
		s.ptr = NULL;
		return s;
	}

	e = plm_queue_get_elem_by_handle(q, q->first);
	if (e->next != NULL_HANDLE) {
		p = plm_queue_get_elem_by_handle(q, e->next);
		p->prev = NULL_HANDLE;
	}
	q->first = e->next;

	q->count--;

	if (q->count == 0)
		q->last = NULL_HANDLE;

	s.size = e->size;
	s.ptr = &e->data;
	return s;
}

bool plm_queue_clear(PlmQueue *q)
{
	vmem_destroy(&q->vm);
	return plm_queue_create(q, q->init_size);
}

void plm_queue_destroy(PlmQueue *q)
{
	vmem_destroy(&q->vm);
	q->count = 0;
	q->first = NULL_HANDLE;
	q->last = NULL_HANDLE;
}

bool plm_queue_is_empty(PlmQueue *q)
{
	return q->count == 0;
}

#endif /* PLM_BS_IMPLEMENTATION */

#ifdef PLM_BS_TEST

#include <stdio.h>
#include <assert.h>

#ifndef PLM_BS_TEST_VERBOSE
# define PLM_BS_TEST_VERBOSE 0
#endif

static void print_chunk(VChunkHdr *chunk, size_t ind, void *context)
{
#if PLM_VMEM_CANARY
	assert(chunk->canary == PLM_VMEM_CANARY_VALUE);
#endif
#if PLM_BS_TEST_VERBOSE
	printf("Chunk %lu: ch->len = %lu; ch->data = %p\n", ind, chunk->len, chunk->data);
#else
	printf("%lu=%lu;", ind, chunk->len);
#endif
}

static int plm_bs_test_vmem(void)
{
	Vmem vm;
	VChunkHdr *chunk;
	char *p;
	size_t l, i, ind;
	char stamp[] = "Iterator test string XXX";

	if (!vmem_create(&vm, 0x3000)) {
		printf("Error: Can't do vmem_create");
		assert(false);
	}

	printf("Simple alloction\n");
	p = vmem_alloc(&vm, 0x120);
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx %p\n\n", l, p);
	assert(l == 0x120);

	printf("Simple string allocation\n");
	p = vmem_stralloc(&vm, "Test string 1 !");
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx; p = '%s' %p\n\n", l, p, p);
	assert(l == 16);

	printf("Allocate a lot of strings\n");
	for (i = 0; i < 60; i++) {
		stamp[21] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		assert(strcmp(p, stamp) == 0);
#if PLM_BS_TEST_VERBOSE
		printf("%lu '%s' %p\n", i, p, p);
#endif
	}
	for (i = 0; i < 60; i++) {
		stamp[22] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		assert(strcmp(p, stamp) == 0);
#if PLM_BS_TEST_VERBOSE
		printf("%lu '%s' %p\n", i, p, p);
#endif
	}
	for (i = 0; i < 60; i++) {
		stamp[23] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		assert(strcmp(p, stamp) == 0);
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
	if (!plm_queue_create(&q, 0x100)) {
		printf("Error: Can't create queue");
		assert(false);
	}
	printf("\n");

	printf("Iterative put\n");
	for (i = 0; i < 0x1000; i++) {
		printf("i=0x%lx;", i);
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		assert(plm_queue_put(&q, stamp2, STAMP_LENGTH));
	}
	printf("\n");

	printf("Iterative get\n");
	for (i = 0; i < 0x1000; i++) {
		printf("i=0x%lx;", i);
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		s = plm_queue_get(&q);
		assert(s.size == STAMP_LENGTH);
		assert(strcmp(s.ptr, stamp2) == 0);
	}
	printf("\n");

	printf("Check empty\n");
	assert(plm_queue_is_empty(&q));
	printf("\n");

	printf("Another put and get\n");
	assert(plm_queue_put(&q, "aaaa", 5));
	s = plm_queue_get(&q);
	assert(s.size == 5);
	assert(strcmp(s.ptr, "aaaa") == 0);
	printf("\n");

	printf("Clear queue\n");
	if (!plm_queue_clear(&q)) {
		printf("Error: Can't clear queue");
		assert(false);
	}
	printf("\n");

	printf("Iterative put\n");
	for (i = 0; i < 0x1000; i++) {
		printf("i=0x%lx;", i);
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		assert(plm_queue_put(&q, stamp2, STAMP_LENGTH));
	}
	printf("\n");

	printf("Iterative get\n");
	for (i = 0; i < 0x1000; i++) {
		printf("i=0x%lx;", i);
		sprintf(stamp2, "XXXXXXXX %010lx XXXXXXX", i);
		s = plm_queue_get(&q);
		assert(s.size == STAMP_LENGTH);
		assert(strcmp(s.ptr, stamp2) == 0);
	}
	printf("\n");

	printf("Check empty\n");
	assert(plm_queue_is_empty(&q));
	printf("\n");

	printf("Another put and get\n");
	assert(plm_queue_put(&q, "aaaa", 5));
	s = plm_queue_get(&q);
	assert(s.size == 5);
	assert(strcmp(s.ptr, "aaaa") == 0);
	printf("\n");

	printf("Destroy queue\n");
	plm_queue_destroy(&q);
	assert(q.vm.ptr == NULL);
	printf("\n");
}

#endif /* PLM_BS_TEST */
