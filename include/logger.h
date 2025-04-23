#ifndef RNVS_LOGGER_H
#define RNVS_LOGGER_H

#include <stdio.h>
#include <dht.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

enum loglevel
{
    NONE,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    FATAL,
};

struct logger
{
    FILE *file;
    enum loglevel loglevel;
};

extern struct logger logger;

int logger_init(FILE *file, enum loglevel loglevel);

int plogf(enum loglevel loglevel, const char *format, ...);

#endif // RNVS_LOGGER_H