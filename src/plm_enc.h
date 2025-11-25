/* plm_enc.h - Encode/decode
 */

#ifndef PLM_ENC_H
#define PLM_ENC_H

#define PLM_ENC_VERSION "0.1.1"

#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/**
 * hex2bin - converts hex to binary
 */
size_t hex2bin(const char *src, uint8_t *out, size_t src_size);

/**
 * bin2hex - converts binary to hex representation
 */
void bin2hex(const uint8_t *src, char *out, size_t src_size);

enum dump_prefix_t {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

/**
 * hexdump - print hexdump of @ptr @length long
 * @ptr: data blob to dump
 * @length: number of bytes to hexdump
 */
extern void hexdump(char *ptr, size_t length);

/**
 * hex_dump_to_buffer - convert a blob of data to "hex ASCII" in memory
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of bytes to print per line; max 64
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @linebuf: where to put the converted data
 * @linebuflen: total size of @linebuf, including space for terminating NUL
 * @ascii: include ASCII after the hex output
 *
 * hex_dump_to_buffer() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of u8 data, hex_dump_to_buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output is always NUL-terminated.
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1,
 *			linebuf, sizeof(linebuf), true);
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 *
 * Return:
 * The amount of bytes placed in the buffer without terminating NUL. If the
 * output was truncated, then the return value is the number of bytes
 * (excluding the terminating NUL) which would have been written to the final
 * string if enough space had been available.
 */
extern int hex_dump_to_buffer(const char *buf, size_t len, int rowsize, int groupsize,
			      char *linebuf, size_t linebuflen, bool ascii);

/**
 * print_hex_dump - print a text hex dump to syslog for a binary blob of data
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (see enum dump_prefix_t)
 * @rowsize: number of bytes to print per line; max 64
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @ascii: include ASCII after the hex output
 * Returns: 0 if finished normally, -EINTR if Ctrl-C was pressed, -ENOSYS if not
 * supported
 *
 * Given a buffer of u8 data, print_hex_dump() prints a hex + ASCII dump
 * to the stdio, with an optional leading prefix.
 *
 * print_hex_dump() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 * print_hex_dump() iterates over the entire input @buf, breaking it into
 * "line size" chunks to format and print.
 *
 * E.g.:
 *   print_hex_dump("raw data: ", DUMP_PREFIX_ADDRESS, 16, 1, frame->data,
 *                  frame->len, true);
 *
 * Example output using %DUMP_PREFIX_OFFSET and 1-byte mode:
 * 0009ab42: 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 * Example output using %DUMP_PREFIX_ADDRESS and 4-byte mode:
 * ffffffff88089af0: 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.
 */
extern int print_hex_dump(const char *prefix_str, int prefix_type, int rowsize,
			  int groupsize, const void *buf, size_t len, bool ascii);

/**
 * is_power_of_2() - check if a value is a power of two
 * @n: the value to check
 *
 * Determine whether some value is a power of two, where zero is
 * *not* considered a power of two.
 * Return: true if @n is a power of 2, otherwise false.
 */
static bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

#endif /* PLM_ENC_H */

#ifdef PLM_ENC_IMPLEMENTATION
#undef PLM_ENC_IMPLEMENTATION

#define hex_asc_lo(x)		     hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)		     hex_asc[((x) & 0xf0) >> 4]
#define min(a, b)		     (((a) < (b)) ? (a) : (b))
#define __get_unaligned_t(type, ptr) ({                        \
	const struct _ {                                       \
		type x;                                        \
	} __attribute__((packed)) *__pptr = (struct _ *)(ptr); \
	__pptr->x;                                             \
})
#define get_unaligned(t, ptr) __get_unaligned_t(t, (ptr))

#define MAX_LINE_LENGTH_BYTES 64

const char hex_asc[] = "0123456789abcdef";

bool hexchr2bin(const char hex, char *out)
{
	if (out == NULL)
		return false;

	if (hex >= '0' && hex <= '9')
		*out = hex - '0';
	else if (hex >= 'A' && hex <= 'F')
		*out = hex - 'A' + 10;
	else if (hex >= 'a' && hex <= 'f')
		*out = hex - 'a' + 10;
	else
		return false;

	return true;
}

size_t hex2bin(const char *src, uint8_t *out, size_t src_size)
{
	size_t out_size;
	char b1;
	char b2;
	size_t i;

	if (src == NULL || *src == '\0' || out == NULL)
		return 0;

	if (src_size % 2 != 0)
		return 0;

	out_size = src_size / 2;

	memset(out, 'A', out_size);
	for (i = 0; i < out_size; i++) {
		if (!hexchr2bin(src[i * 2], &b1) || !hexchr2bin(src[i * 2 + 1], &b2))
			return 0;
		out[i] = (b1 << 4) | b2;
	}

	return out_size;
}

void bin2hex(const uint8_t *src, char *out, size_t src_size)
{
	size_t i, j;
	for (i = 0; i < src_size; i++) {
		out[i * 2] = hex_asc_hi(src[i]);
		out[i * 2 + 1] = hex_asc_lo(src[i]);
	}
	out[src_size * 2] = '\0';
}

void hexdump(char *ptr, size_t length)
{
	print_hex_dump("", DUMP_PREFIX_ADDRESS, 16, 1, ptr, length, true);
}

int hex_dump_to_buffer(const char *buf, size_t len, int rowsize, int groupsize,
		       char *linebuf, size_t linebuflen, bool ascii)
{
	const char *ptr = buf;
	int ngroups;
	u8 ch;
	int j, lx = 0;
	int ascii_column;
	int ret;

	if (!rowsize)
		rowsize = 16;
	else
		rowsize = min(rowsize, MAX_LINE_LENGTH_BYTES);

	if (len > rowsize) /* limit to one line at a time */
		len = rowsize;
	if (!is_power_of_2(groupsize) || groupsize > 8)
		groupsize = 1;
	if ((len % groupsize) != 0) /* no mixed size output */
		groupsize = 1;

	ngroups = len / groupsize;
	ascii_column = rowsize * 2 + rowsize / groupsize + 1;

	if (!linebuflen)
		goto overflow1;

	if (!len)
		goto nil;

	if (groupsize == 8) {
		const u64 *ptr8 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%16.16llx", j ? " " : "",
				       get_unaligned(u64, ptr8 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else if (groupsize == 4) {
		const u32 *ptr4 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%8.8x", j ? " " : "",
				       get_unaligned(u32, ptr4 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else if (groupsize == 2) {
		const u16 *ptr2 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%4.4x", j ? " " : "",
				       get_unaligned(u16, ptr2 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else {
		for (j = 0; j < len; j++) {
			if (linebuflen < lx + 2)
				goto overflow2;
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = hex_asc_lo(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = ' ';
		}
		if (j)
			lx--;
	}
	if (!ascii)
		goto nil;

	while (lx < ascii_column) {
		if (linebuflen < lx + 2)
			goto overflow2;
		linebuf[lx++] = ' ';
	}
	for (j = 0; j < len; j++) {
		if (linebuflen < lx + 2)
			goto overflow2;
		ch = ptr[j];
		linebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	linebuf[lx] = '\0';
	return lx;
overflow2:
	linebuf[lx++] = '\0';
overflow1:
	return ascii ? ascii_column + len : (groupsize * 2 + 1) * ngroups - 1;
}

int print_hex_dump(const char *prefix_str, int prefix_type, int rowsize,
		   int groupsize, const void *buf, size_t len, bool ascii)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	char linebuf[MAX_LINE_LENGTH_BYTES * 3 + 2 + MAX_LINE_LENGTH_BYTES + 1];

	if (!rowsize)
		rowsize = 16;
	else
		rowsize = min(rowsize, MAX_LINE_LENGTH_BYTES);

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			printf("%s%0*lx: %s\n", prefix_str,
			       sizeof(uintptr_t) * 2,
			       (uintptr_t)(ptr) + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			printf("%s%.8x: %s\n", prefix_str, i, linebuf);
			break;
		default:
			printf("%s%s\n", prefix_str, linebuf);
			break;
		}
	}

	return 0;
}

#endif /* PLM_BS_IMPLEMENTATION */

#ifdef PLM_ENC_TEST

void plm_enc_test_hexdump()
{
	hexdump(hexdump, 0x201);
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

	bin = malloc(strlen(hex) / 2 + 10);
	binlen = hex2bin(hex, bin, strlen(hex));
	printf("%ld, %s\n", (int)binlen, (char *)bin);

	free(bin);
	free(hex);
}

#endif /* PLM_ENC_TEST */
