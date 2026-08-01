#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

void plm_enc_test_hexdump()
{
	hexdump((void*)hexdump, 0x201);
}

void plm_enc_test_bin2hex_hex2bin()
{
	const char *a = "Test 123! - jklmn";
	char *hex;
	uint8_t *bin;
	size_t binlen;

	hex = malloc(strlen(a) * 2 + 1);
	bin2hex((uint8_t *)a, hex, strlen(a));
	printf("\n%s\n", hex);
	assert_memory_equal(hex, "546573742031323321202d206a6b6c6d6e", strlen(a));

	bin = malloc(strlen(hex) / 2 + 10);
	binlen = hex2bin(hex, bin, strlen(hex));
	printf("%ld, %s\n", (long int)binlen, (char *)bin);
	assert_memory_equal((char *)bin, a, binlen);

	free(bin);
	free(hex);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(plm_enc_test_hexdump),
		cmocka_unit_test(plm_enc_test_bin2hex_hex2bin),
	};

	if (argc > 1)
		cmocka_set_test_filter(argv[1]);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
