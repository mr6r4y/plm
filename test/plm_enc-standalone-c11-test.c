#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

int main(void)
{
	char output[3];
	const uint8_t input = 0;

	return bin2hex(&input, output, 1) == sizeof(output) ? 0 : 1;
}
