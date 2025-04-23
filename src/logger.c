// Path: src/logger.c
#include <logger.h>

#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <string.h>

struct logger logger = {
    .file = NULL,
};

int logger_init(FILE *file, enum loglevel loglevel)
{
    logger.loglevel = loglevel;
    if (logger.file != NULL)
        return -1;
    logger.file = file;
    return 0;
}

int plogf(enum loglevel loglevel, const char *format, ...)
{
    if (loglevel < logger.loglevel)
        return 0;

    size_t ret = 0;
    int status = 1;

    // check if logger is initialised
    if (logger.file == NULL)
    {
        fprintf(stderr, "logger is not initialised.\n");
        return -1;
    }

    // va_list is a type that allows us to iterate through a variadic list of
    // arguments
    va_list args;

    // va_start is a macro that initializes the va_list
    va_start(args, format);

    // print the log level and time to the log file
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);

    char *loglevel_str = "???";

    switch (loglevel)
    {
    case DEBUG:
        loglevel_str = ANSI_COLOR_BLUE "DBG" ANSI_COLOR_RESET;
        break;
    case INFO:
        loglevel_str = ANSI_COLOR_GREEN "NFO" ANSI_COLOR_RESET;
        break;
    case WARNING:
        loglevel_str = ANSI_COLOR_YELLOW "WRN" ANSI_COLOR_RESET;
        break;
    case ERROR:
        loglevel_str = ANSI_COLOR_RED "ERR" ANSI_COLOR_RESET;
        break;
    case FATAL:
        loglevel_str = ANSI_COLOR_MAGENTA "FAT" ANSI_COLOR_RESET;
        break;
    case NONE:
        break;
    }

    if (loglevel != NONE)
    {
        status = fprintf(logger.file, "%s [%d-%02d-%02d@%02d:%02d:%02d] (%d) ", loglevel_str, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, self.id);
        if (status < 0)
        {
            fprintf(stderr, "logf: fprintf failed\n");
            return -1;
        }
        ret += status;
    }

    // print variadic arguments to the log file
    status = vfprintf(logger.file, format, args);
    if (status < 0)
    {
        fprintf(stderr, "logf: vfprintf failed\n");
        return -1;
    }
    ret += status;
    putc('\n', logger.file);

    // printf if at sufficient loglevel and errno is set
    if ((loglevel == ERROR || loglevel == FATAL) && errno != 0)
    {
        status = fprintf(logger.file, "-- Errno Message --\n%s\n-- End Errno Msg --\n", strerror(errno));
        if (status < 0)
        {
            fprintf(stderr, "logf: fprintf failed during strerror\n");
            return -1;
        }
        ret += status;
    }

    va_end(args);

    return ret;
}