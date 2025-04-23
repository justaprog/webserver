#include <util.h>

#include <logger.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

char *memstr(char *haystack, size_t n, string needle)
{
    char *end = haystack + n;

    // Iterate through the memory (haystack)
    while ((haystack = memchr(haystack, needle[0], end - haystack)) != NULL)
    {
        if (strncmp(haystack, needle, strlen(needle)) == 0)
        {
            return haystack;
        }
    }

    return NULL;
}

uint16_t safe_strtoul(const char *restrict nptr, char **restrict endptr, int base, const string message)
{
    unsigned long result = strtoul(nptr, endptr, base); // Convert string to unsigned int

    if (result == ULONG_MAX)
    {
        plogf(FATAL, "%s", message);
        exit(EXIT_FAILURE);
    }


    return result;
}
