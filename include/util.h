#pragma once

#include <stdlib.h>
#include <stdint.h>


typedef char* string; // differentiate null-terminated C-string from bytes

/**
 * Analog to `strstr()`, for non-C-string haystacks.
 */
char* memstr(char* haystack, size_t n, string needle);

/**
 * Safe version of `strtoul()`
 *
 * Will return the result of strtoul, unless an error occurs.
 * In that case, the given message will be printed before exiting the program.
 */
uint16_t safe_strtoul(const char *restrict nptr, char **restrict endptr, int base, const string message);
