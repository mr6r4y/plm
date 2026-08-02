#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>

#define PLM_BS_IMPLEMENTATION
#include "plm_bs.h"

#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

int main(void)
{
	Vmem vm;
	const size_t size = 64;
	char *s;
	char hex[3];
	const uint8_t byte = 0xab;

	if (!vmem_create(&vm, size * 2))
		return 1;
	s = vmem_alloc(&vm, size);
	if (!s) {
		vmem_destroy(&vm);
		return 2;
	}
	memset(s, 0, size);
	if (bin2hex(&byte, hex, 1) != sizeof(hex) || strcmp(hex, "ab") != 0) {
		vmem_destroy(&vm);
		return 3;
	}
	vmem_destroy(&vm);
	return 0;
}
