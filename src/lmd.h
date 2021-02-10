#ifndef LMD_H
#define LMD_H

#include <ev.h>

#include "cor_core.h"
#include "cor_log.h"
#include "cor_http.h"

typedef struct
{
    cor_http_config_t http_config;

    cor_http_t *http;
    cor_log_t *log;
    struct ev_loop *loop;
} lmd_ctx_t;


#endif