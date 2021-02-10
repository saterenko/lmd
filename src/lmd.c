#include <stdio.h>

#include "lmd.h"

static void lmd_delete(lmd_ctx_t *ctx);
static void lmd_http_cb(cor_http_request_t *r, void *arg);

int
main(int argc, char **argv)
{
    lmd_ctx_t ctx;
    memset(&ctx, 0, sizeof(lmd_ctx_t));
    /**/
    ctx.log = cor_log_new("lmd.log", cor_log_level_debug);
    if (!ctx.log) {
        fprintf(stderr, "can't cor_log_new\n");
        return 1;
    }
    /**/
    ctx.loop = ev_loop_new(EVFLAG_AUTO);
    /**/
    ctx.http_config.max_request_size = 32 * 1024;
    ctx.http_config.read_timeout = 1000;
    ctx.http_config.write_timeout = 1000;
    ctx.http_config.keep_alive_timeout = 60;
    /**/
    ctx.http = cor_http_new(ctx.loop, "127.0.0.1", 13001, &ctx.http_config, ctx.log);
    if (!ctx.http) {
        cor_log_error(ctx.log, "can't cor_http_new");
        lmd_delete(&ctx);
        return 1;
    }
    if (cor_http_start(ctx.http, lmd_http_cb, &ctx) != cor_ok) {
        cor_log_error(ctx.log, "can't cor_http_start");
        lmd_delete(&ctx);
        return 1;
    }
    /**/
    ev_run(ctx.loop, 0);
    /**/
    cor_log_delete(ctx.log);
    return 0;
}

void
lmd_delete(lmd_ctx_t *ctx)
{
    if (ctx) {
        if (ctx->http) {
            cor_http_delete(ctx->http);
        }
        if (ctx->log) {
            cor_log_delete(ctx->log);
        }
        if (ctx->loop) {
            ev_loop_destroy(ctx->loop);
        }
    }
}

static void
lmd_http_cb(cor_http_request_t *r, void *arg)
{
    lmd_ctx_t *ctx = (lmd_ctx_t *) arg;
    cor_log_debug(ctx->log, "request handled, sd: %d", r->sd);
    /**/
    cor_http_response_t res;
    cor_http_response_init(&res, r);
    cor_http_response_set_code(&res, 200);
    cor_http_response_set_body(&res, "answer", 6);
    cor_http_response_send(&res);
}
