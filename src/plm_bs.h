/* plm_bs.h - v0.1 - basic data structures and memory allocation primitives - plm 2025
 */

#ifndef PLM_BS_H
#define PLM_BS_H

#include <stdbool.h>
#include <stddef.h>
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

typedef enum {
	NO_ERROR = 0,
	NO_MEMORY,
} VmemErrorType;

typedef struct {
	bool is_error;
	VmemErrorType error_type;
} VmemStatus;

VmemStatus vmem_create(Vmem *vmem, size_t init_alloc, size_t realloc_step);
void *vmem_alloc(Vmem *vmem, size_t size);
size_t vmem_chunk_size_get(Vmem *vmem, void *chunk_ptr);
void *vmem_chunk_get_by_index(Vmem *vmem, size_t ind);
VmemStatus vmem_clear(Vmem *vmem);
VmemStatus vmem_destroy(Vmem *vmem);

#endif /* PLM_BS_H */

#ifdef PLM_BS_IMPLEMENTATION

#endif /* PLM_BS_IMPLEMENTATION */

#ifdef PLM_BS_TEST

int main(int argc, char **argv)
{
}

#endif /* PLM_BS_TEST */
