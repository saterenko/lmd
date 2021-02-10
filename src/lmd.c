#include <stdio.h>

#include "lmd.h"

static void lmd_delete(lmd_ctx_t *ctx);
static void lmd_http_cb(cor_http_request_t *r, void *arg);
static void lmd_command_set_limits(cor_http_request_t *r);

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
    cor_log_debug(ctx->log, "path: %.*s", (int) r->path.size, r->path.data);
    switch (r->method) {
        case COR_HTTP_POST:
            switch (r->path.size) {
                case 11:
                    if (strncmp(r->path.data, "/set-limits", 11) == 0) {
                        return lmd_command_set_limits(r);
                    }
                    break;
            }
            break;
    }
    cor_log_warn(ctx->log, "bad request, method %s, path: %.*s", cor_http_method_name(r->method),
        (int) r->path.size, r->path.data);
    /**/
    cor_http_response_t res;
    cor_http_response_init(&res, r);
    cor_http_response_set_code(&res, 400);
    cor_http_response_set_body(&res, "bad request", 11);
    cor_http_response_send(&res);
}

static void
lmd_command_set_limits(cor_http_request_t *r)
{
    cor_http_response_t res;
    cor_http_response_init(&res, r);
    cor_http_response_set_code(&res, 200);
    cor_http_response_set_body(&res, "set-limits", 10);
    cor_http_response_send(&res);
}
