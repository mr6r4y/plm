#define PLM_BS_IMPLEMENTATION
#include "plm_bs.h"

#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

int main()
{
	Vmem memory{};
	char output[3]{};
	const uint8_t input = 0;

	if (!vmem_create(&memory, 64))
		return 1;
	(void)bin2hex(&input, output, 1);
	vmem_destroy(&memory);
	return 0;
}
