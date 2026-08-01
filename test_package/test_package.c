#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#define PLM_BS_IMPLEMENTATION
#include "plm_bs.h"

#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

int main(void)
{
	Vmem vm;
	size_t size;
	char *s;
	vmem_create(&vm, size * 2);
	s = vmem_alloc(&vm, size);
	return 0;
}
