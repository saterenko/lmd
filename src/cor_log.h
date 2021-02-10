#ifndef COR_LOG_H
#define COR_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cor_core.h"

enum cor_log_level_e
{
    cor_log_level_error = 0,
    cor_log_level_warn,
    cor_log_level_info,
    cor_log_level_debug
};

#define COR_LOG_TIME_STR_SIZE sizeof("[YYYY.MM.DD HH:MM:SS] ")
#define COR_LOG_PID_STR_SIZE sizeof("-18446744073709551615")
#define COR_LOG_STR_SIZE 1024
#define COR_LOG_STR_MAX_SIZE 64 * 1024

#define cor_log_error(log, args...) cor_log_put(log, cor_log_level_error, __FILE__, __LINE__, args)
#define cor_log_warn(log, args...) cor_log_put(log, cor_log_level_warn, __FILE__, __LINE__, args)
#define cor_log_info(log, args...) cor_log_put(log, cor_log_level_info, __FILE__, __LINE__, args)
#define cor_log_debug(log, args...) cor_log_put(log, cor_log_level_debug, __FILE__, __LINE__, args)

typedef struct
{
    int level;
    time_t ts;
    size_t max_line_size;
    char ts_str[COR_LOG_TIME_STR_SIZE];
    char pid_str[COR_LOG_PID_STR_SIZE];
    FILE *fd;
} cor_log_t;

cor_log_t *cor_log_new(const char *file, int level);
void cor_log_set_pid(cor_log_t *log, pid_t pid);
void cor_log_set_str_level(cor_log_t *log, const char *level);
void cor_log_put(cor_log_t *log, enum cor_log_level_e level, const char *file, int line, const char *format, ...);
void cor_log_delete(cor_log_t *log);

#endif
