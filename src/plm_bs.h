/* plm_bs.h - v0.1 - basic data structures and memory allocation primitives - plm 2025
 */

#ifndef PLM_BS_H
#define PLM_BS_H

#include <stdbool.h>
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
	size_t alloc;
	size_t realloc_step;
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

extern bool vmem_create(Vmem *vmem, size_t init_alloc, size_t realloc_step);
extern void *vmem_alloc(Vmem *vmem, size_t size);
extern char *vmem_stralloc(Vmem *vmem, const char *s);
extern size_t vmem_chunk_size_get(void *ptr);
extern VChunkHdr *vmem_chunk_get_by_index(Vmem *vmem, size_t ind);
extern void vmem_chunk_iter(Vmem *vmem, VmemChunkIterCallback clb, void *context);
extern void vmem_clear(Vmem *vmem);
extern void vmem_destroy(Vmem *vmem);

#endif /* PLM_BS_H */

#ifdef PLM_BS_IMPLEMENTATION

static char *plm_strncpy(char *d, const char *s, size_t n)
{
	for (; n && (*d = *s); n--, s++, d++)
		;
	d[n] = '\0';
	return d;
}

static size_t plm_strlen(const char *s)
{
	const char *a = s;
	for (; *s; s++)
		;
	return s - a;
}

bool vmem_create(Vmem *vmem, size_t init_alloc, size_t realloc_step)
{
	size_t alloc, min_size;

	if (init_alloc < 1)
		return false;

	vmem->ptr = plm_malloc(init_alloc);

	if (!vmem->ptr)
		return false;

	vmem->len = 0;
	vmem->alloc = init_alloc;
	vmem->realloc_step = realloc_step;
	vmem->end = 0;

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

void *vmem_alloc(Vmem *vmem, size_t size)
{
	size_t align, free, ch_size, extra_alloc;
	VChunkHdr *chunk;

	free = vmem->alloc - vmem->end;
	align = sizeof(size_t);
	ch_size = sizeof(VChunkHdr) + size;
	ch_size = ch_size + align - (ch_size & (align - 1));

	if (free < ch_size) {
		extra_alloc = ch_size - free + vmem->realloc_step;
		vmem->ptr = plm_realloc(vmem->ptr, vmem->alloc + extra_alloc);
		if (!vmem->ptr)
			return false;
		vmem->alloc += extra_alloc;
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
	l = plm_strlen(s);
	p = vmem_alloc(vmem, l + 1);
	if (!p)
		return NULL;
	plm_strncpy(p, s, l);
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
		ch_size = vmem_chunk_size(ch);
		ch = (VChunkHdr *)((uintptr_t)ch + ch_size);

		i++;
	}

	return ch;
}

void vmem_chunk_iter(Vmem *vmem, VmemChunkIterCallback clb, void *context)
{
	VChunkHdr *ch;
	size_t i = 0;
	size_t ch_size;

	ch = (VChunkHdr *)vmem->ptr;
	for (i = 0; i < vmem->len; i++) {
		clb(ch, i, context);
		ch_size = vmem_chunk_size(ch);
		ch = (VChunkHdr *)((uintptr_t)ch + ch_size);
	}
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

#endif /* PLM_BS_IMPLEMENTATION */

#ifdef PLM_BS_TEST

#include <stdio.h>
#include <assert.h>

static void print_chunk(VChunkHdr *chunk, size_t ind, void *context)
{
	printf("Chunk %lu: ch->len = %lu; ch->data = %p\n", ind, chunk->len, chunk->data);
}

static int plm_bs_smoke_test(void)
{
	Vmem vm;
	VChunkHdr *chunk;
	char *p;
	size_t l, i, ind;
	char stamp[] = "Iterator test string XXX";

	if (!vmem_create(&vm, 0x1000, 0x1000))
		printf("Error: Can't do vmem_create");

	printf("Simple alloction\n");
	p = vmem_alloc(&vm, 0x120);
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx %p\n\n", l, p);

	printf("Simple string allocation\n");
	p = vmem_stralloc(&vm, "Test string 1 !");
	l = vmem_chunk_size_get(p);
	printf("p->size = 0x%lx; p = '%s' %p\n\n", l, p, p);

	printf("Allocate a lot of strings\n");
	for (i = 0; i < 60; i++) {
		stamp[21] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		printf("%lu '%s' %p\n", i, p, p);
	}
	for (i = 0; i < 60; i++) {
		stamp[22] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		printf("%lu '%s' %p\n", i, p, p);
	}
	for (i = 0; i < 60; i++) {
		stamp[23] = ' ' + i;
		p = vmem_stralloc(&vm, stamp);
		printf("%lu '%s' %p\n", i, p, p);
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
	printf("vmem->len = 0x%lx; vmem->alloc = 0x%lx; vmem->end = 0x%lx; vmem->ptr = %p\n\n", vm.len, vm.alloc, vm.end, vm.ptr);

	printf("\nTest chunk iterator:\n");
	vmem_chunk_iter(&vm, print_chunk, NULL);

	printf("\nDeallocate everything\n\n");
	vmem_destroy(&vm);
}

#endif /* PLM_BS_TEST */
