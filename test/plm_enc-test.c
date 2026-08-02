#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define PLM_ENC_IMPLEMENTATION
#include "plm_enc.h"

static void plm_enc_test_hexdump(void **state)
{
	const uint8_t input[] = { 0x40, 0x41, 0x00, 0x7f };
	char line[64];
	int length;

	(void)state;
	length = hex_dump_to_buffer((const char *)input, sizeof(input), 16, 1,
				    line, sizeof(line), false);
	assert_int_equal(length, 11);
	assert_string_equal(line, "40 41 00 7f");
}

static void plm_enc_test_bin2hex_hex2bin(void **state)
{
	static const char plain[] = "Test 123! - jklmn";
	static const char expected_hex[] = "546573742031323321202d206a6b6c6d6e";
	char hex[sizeof(expected_hex)];
	uint8_t binary[sizeof(plain) - 1];
	size_t hex_length;
	size_t binary_length;

	(void)state;
	hex_length = bin2hex((const uint8_t *)plain, hex, sizeof(plain) - 1);
	assert_int_equal(hex_length, sizeof(expected_hex));
	assert_string_equal(hex, expected_hex);

	binary_length = hex2bin(hex, binary, strlen(hex));
	assert_int_equal(binary_length, sizeof(binary));
	assert_memory_equal(binary, plain, binary_length);
}

static void plm_enc_test_negative_rowsize_uses_default(void **state)
{
	uint8_t input[128];
	char line[512];
	int length;

	(void)state;
	memset(input, 0x22, sizeof(input));
	memset(input, 0x11, 16);
	length = hex_dump_to_buffer((const char *)input, sizeof(input), -1, 1,
				    line, sizeof(line), false);

	/* A non-positive row size must use the documented/default 16-byte row. */
	assert_int_equal(length, 16 * 3 - 1);
	assert_int_equal(strlen(line), 16 * 3 - 1);
	assert_null(strstr(line, "22"));
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(plm_enc_test_hexdump),
		cmocka_unit_test(plm_enc_test_bin2hex_hex2bin),
		cmocka_unit_test(plm_enc_test_negative_rowsize_uses_default),
	};

	if (argc > 1)
		cmocka_set_test_filter(argv[1]);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
