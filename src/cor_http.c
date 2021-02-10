#include "cor_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define COR_HTTP_DEFAULT_BACKLOG_SIZE 1024
#define COR_HTTP_DEFAULT_BUF_COUNT 256
#define COR_HTTP_DEFAULT_BUF_SIZE 4096
#define COR_HTTP_DEFAULT_REQUEST_POOL_SIZE 1024
#define COR_HTTP_DEFAULT_MAX_REQUEST_SIZE (1024 * 1024)
#define COR_HTTP_DEFAULT_KEEP_ALIVE_TIMEOUT 30

static void cor_http_config_init(cor_http_t *ctx, cor_http_config_t *config);
static int cor_http_listener_init(cor_http_t *ctx);
static cor_http_request_t *cor_http_request_new(cor_http_t *ctx);
static void cor_http_listen_cb(struct ev_loop *loop, ev_io *w, int ev_fl);
static void cor_http_request_ev_cb(struct ev_loop *loop, ev_io *w, int ev_fl);
static void cor_http_request_timer_cb(EV_P_ ev_timer *w, int ev_fl);
static void cor_http_request_process(cor_http_request_t *r);
static int cor_http_request_read(cor_http_request_t *r);
static int cor_http_request_write(cor_http_request_t *r);
static void cor_http_request_close(cor_http_request_t *r);
static void cor_http_request_reset(cor_http_request_t *r);
static inline void cor_http_request_set_conn_state(cor_http_request_t *r, int state);
static int cor_http_parse(cor_http_request_t *r);
static inline int cor_http_parse_add_param(cor_http_request_t *r, unsigned int hash);
static inline int cor_http_parse_add_header(cor_http_request_t *r, unsigned int hash);
static inline int cor_http_parse_add_cookie(cor_http_request_t *r, unsigned int hash);
static inline int cor_http_url_decode(char *p, int size);
static void cor_http_after_parse(cor_http_request_t *r);

cor_http_t *
cor_http_new(struct ev_loop *loop, const char *host, int port,
    cor_http_config_t *config, cor_log_t *log)
{
    size_t host_len = strlen(host);
    cor_http_t *ctx = malloc(sizeof(cor_http_t) + host_len + 1);
    if (!ctx) {
        cor_log_error(log, "can't malloc");
        return NULL;
    }
    memset(ctx, 0, sizeof(cor_http_t));
    cor_http_config_init(ctx, config);
    ctx->host = (char *) ctx + sizeof(cor_http_t);
    memcpy(ctx->host, host, host_len + 1);
    ctx->port = port;
    ctx->loop = loop;
    ctx->log = log;
    /**/
    ctx->buf_pool = cor_buf_pool_new(ctx->config.buf_count, ctx->config.buf_size);
    if (!ctx->buf_pool) {
        cor_log_error(log, "can't cor_buf_pool_new");
        cor_http_delete(ctx);
        return NULL;
    }
    ctx->requests = cor_list_new(ctx->config.buf_count, sizeof(cor_http_request_t));
    if (!ctx->requests) {
        cor_log_error(log, "can't cor_list_new");
        cor_http_delete(ctx);
        return NULL;
    }

    return ctx;
}

void
cor_http_delete(cor_http_t *ctx)
{
    if (ctx) {
        if (ctx->listen) {
            cor_http_request_close(ctx->listen);
        }
        if (ctx->requests) {
            cor_list_block_t *b;
            b = &ctx->requests->root;
            cor_http_request_t *requests = (cor_http_request_t *) b->elts;
            for (int i = 0; ; i++) {
                if (i == b->nelts) {
                    if (!b->next) {
                        break;
                    }
                    b = b->next;
                    requests = (cor_http_request_t *) b->elts;
                    i = 0; 
                }
                cor_http_request_close(&requests[i]);
                if (requests[i].pool) {
                    cor_pool_delete(requests[i].pool);
                    requests[i].pool = NULL;
                }
            }
            cor_list_delete(ctx->requests);
        }
        if (ctx->buf_pool) {
            cor_buf_pool_delete(ctx->buf_pool);
        }
        free(ctx);
    }
}

int
cor_http_start(cor_http_t *ctx, cor_http_cb_t *cb, void *arg)
{
    ctx->cb = cb;
    ctx->arg = arg;
    if (cor_http_listener_init(ctx) != cor_ok) {
        cor_log_error(ctx->log, "can't cor_http_listener_init");
        return cor_error;
    }
    return cor_ok;
}

cor_str_t *
cor_http_request_get_param(cor_http_request_t *r, const char *key, int size)
{
    unsigned int hash = 0;
    for (int i = 0; i < size; ++i) {
        hash = cor_hash(hash, key[i]);
    }
    cor_http_param_t *params = (cor_http_param_t *) r->params.elts;
    for (int i = 0; i < r->params.nelts; ++i) {
        if (params[i].hash == hash && strncmp(params[i].key.data, key, size) == 0) {
            return &params[i].value;
        }
    }

    return NULL;
}

cor_str_t *
cor_http_request_get_header(cor_http_request_t *r, const char *key, int size)
{
    unsigned int hash = 0;
    for (int i = 0; i < size; ++i) {
        hash = cor_hash(hash, key[i]);
    }
    cor_http_header_t *headers = (cor_http_header_t *) r->headers.elts;
    for (int i = 0; i < r->headers.nelts; ++i) {
        if (headers[i].hash == hash && strncmp(headers[i].key.data, key, size) == 0) {
            return &headers[i].value;
        }
    }

    return NULL;
}

cor_str_t *
cor_http_request_get_cookie(cor_http_request_t *r, const char *key, int size)
{
    unsigned int hash = 0;
    for (int i = 0; i < size; ++i) {
        hash = cor_hash(hash, key[i]);
    }
    cor_http_cookie_t *cookies = (cor_http_cookie_t *) r->cookies.elts;
    for (int i = 0; i < r->cookies.nelts; ++i) {
        if (cookies[i].hash == hash && strncmp(cookies[i].key.data, key, size) == 0) {
            return &cookies[i].value;
        }
    }

    return NULL;
}

cor_http_response_t *
cor_http_response_new(cor_http_request_t *request)
{
    cor_http_response_t *r = cor_pool_calloc(request->pool, sizeof(cor_http_response_t));
    if (!r) {
        cor_log_error(request->ctx->log, "can't cor_pool_calloc");
        return NULL;
    }
    r->request = request;

    return r;
}

void
cor_http_response_init(cor_http_response_t *r, cor_http_request_t *request)
{
    memset(r, 0, sizeof(cor_http_response_t));
    r->request = request;
}

void
cor_http_response_set_code(cor_http_response_t *r, int code)
{
    r->code = code;
}

void
cor_http_response_set_body(cor_http_response_t *r, const char *data, int size)
{
    r->body = data;
    r->body_size = size;
}

int
cor_http_response_add_header(cor_http_response_t *r, cor_http_header_t *header)
{
    cor_http_request_t *request = r->request;
    cor_http_t *ctx = request->ctx;
    if (!r->headers.elts) {
        if (cor_array_init(&r->headers, request->pool, 1, sizeof(cor_http_header_t)) != cor_ok) {
            cor_log_error(ctx->log, "can't cor_array_init");
            return cor_error;
        }
    }
    cor_http_header_t *h = cor_array_push(&r->headers);
    if (!h) {
        cor_log_error(ctx->log, "can't cor_array_push");
        return cor_error;
    }
    memcpy(h, header, sizeof(cor_http_header_t));

    return cor_ok;
}

int
cor_http_response_add_cookie(cor_http_response_t *r, cor_http_cookie_t *cookie)
{
    cor_http_request_t *request = r->request;
    cor_http_t *ctx = request->ctx;
    if (!r->cookies.elts) {
        if (cor_array_init(&r->cookies, request->pool, 1, sizeof(cor_http_cookie_t)) != cor_ok) {
            cor_log_error(ctx->log, "can't cor_array_init");
            return cor_error;
        }
    }
    cor_http_cookie_t *c = cor_array_push(&r->cookies);
    if (!c) {
        cor_log_error(ctx->log, "can't cor_array_push");
        return cor_error;
    }
    memcpy(c, cookie, sizeof(cor_http_cookie_t));

    return cor_ok;
}

int
cor_http_response_send(cor_http_response_t *r)
{
    static char response200[] = "HTTP/1.1 200 OK\r\n";
    static char response302[] = "HTTP/1.1 302 Found\r\n";
    static char response400[] = "HTTP/1.1 400 Bad Request\r\n";
    static char response404[] = "HTTP/1.1 404 Not Found\r\n";
    static char response405[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    static char response500[] = "HTTP/1.1 500 Internal Server Error\r\n";
    static char response501[] = "HTTP/1.1 501 Not Implemented\r\n";
    static char response_keep_alive[] = "Connection: keep-alive\r\n";
    static char response_close[] = "Connection: close\r\n";
    /**/
    cor_http_request_t *request = r->request;
    if (!request) {
        return cor_error;
    }
    cor_http_t *ctx = request->ctx;
    /**/
    switch (r->code) {
        case 200:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response200, sizeof(response200) - 1);
            break;
        case 302:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response302, sizeof(response302) - 1);
            break;
        case 400:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response400, sizeof(response400) - 1);
            break;
        case 404:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response404, sizeof(response404) - 1);
            break;
        case 405:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response405, sizeof(response405) - 1);
            break;
        case 501:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response501, sizeof(response501) - 1);
            break;
        default:
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response500, sizeof(response500) - 1);
            break;
    }
    /*  write connection header  */
    if (request->keep_alive) {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response_keep_alive, sizeof(response_keep_alive) - 1);
    } else {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, response_close, sizeof(response_close) - 1);
    }
    /*  write user headers  */
    cor_http_header_t *headers = (cor_http_header_t *) r->headers.elts;
    for (int i = 0; i < r->headers.nelts; ++i) {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, headers[i].key.data, headers[i].key.size);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ": ", 2);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, headers[i].value.data, headers[i].value.size);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "\r\n", 2);
    }
    /*  write cookies  */
    cor_http_cookie_t *cookies = (cor_http_cookie_t *) r->cookies.elts;
    for (int i = 0; i < r->cookies.nelts; ++i) {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "Set-Cookie: ", sizeof("Set-Cookie: ") - 1);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, cookies[i].key.data, cookies[i].key.size);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "=", 1);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, cookies[i].value.data, cookies[i].value.size);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ";", 1);
        if (cookies[i].domain.size) {
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, " domain=", sizeof(" domain=") - 1);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, cookies[i].domain.data, cookies[i].domain.size);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ";", 1);
        }
        if (cookies[i].path.size) {
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, " path=", sizeof(" path=") - 1);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, cookies[i].path.data, cookies[i].path.size);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ";", 1);
        }
        if (cookies[i].exp) {
            /*  cache cookie expire time  */
            if (request->created + cookies[i].exp != ctx->cookie_expires_timestamp) {
                ctx->cookie_expires_timestamp = request->created + cookies[i].exp;
                struct tm ltm;
                gmtime_r(&ctx->cookie_expires_timestamp, &ltm);
                ctx->cookie_expires_str_size = strftime(ctx->cookie_expires_str, COR_HTTP_COOKIE_EXPIRE_STR_SIZE,
                    "%a, %d-%b-%Y %H:%M:%S GMT", &ltm);
            }
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, " expires=", sizeof(" expires=") - 1);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ctx->cookie_expires_str, ctx->cookie_expires_str_size);
            cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, ";", 1);
        }
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "\r\n", 2);
    }
    /*  wite body  */
    if (r->body_size) {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "Content-Length: ", sizeof("Content-Length: ") - 1);
        char num[20];
        int rc = cor_str_itoa(r->body_size, num);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, num, rc);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "\r\n\r\n", 4);
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, r->body, r->body_size);
    } else {
        cor_buf_chain_append_data(ctx->buf_pool, &request->write_bufs, "Content-Length: 0\r\n\r\n", sizeof("Content-Length: 0\r\n\r\n") - 1);
    }
    /*  write  */
    if (ctx->config.write_timeout) {
        ev_timer_set(&request->timer, (double) ctx->config.write_timeout / 1000.0, 0.0);
        ev_timer_start(ctx->loop, &request->timer);
    }
    cor_http_request_set_conn_state(request, COR_HTTP_WRITE);
    if (!request->dont_process_fsm) {
        if (ev_is_active(&request->ev)) {
            ev_io_stop(ctx->loop, &request->ev);
        }
        cor_http_request_process(request);
    }

    return cor_ok;
}

static void
cor_http_config_init(cor_http_t *ctx, cor_http_config_t *config)
{
    ctx->config.backlog_size = COR_HTTP_DEFAULT_BACKLOG_SIZE;
    ctx->config.buf_count = COR_HTTP_DEFAULT_BUF_COUNT;
    ctx->config.buf_size = COR_HTTP_DEFAULT_BUF_SIZE;
    ctx->config.request_pool_size = COR_HTTP_DEFAULT_REQUEST_POOL_SIZE;
    ctx->config.max_request_size = COR_HTTP_DEFAULT_MAX_REQUEST_SIZE;
    ctx->config.read_timeout = 0;
    ctx->config.write_timeout = 0;
    ctx->config.keep_alive_timeout = COR_HTTP_DEFAULT_KEEP_ALIVE_TIMEOUT;
    /**/
    if (config) {
#define COR_HTTP_SET_CONFIG(_k) \
        if (config->_k) { \
            ctx->config._k = config->_k; \
        }

        COR_HTTP_SET_CONFIG(backlog_size);
        COR_HTTP_SET_CONFIG(buf_count);
        COR_HTTP_SET_CONFIG(buf_size);
        COR_HTTP_SET_CONFIG(request_pool_size);
        COR_HTTP_SET_CONFIG(max_request_size);
        COR_HTTP_SET_CONFIG(read_timeout);
        COR_HTTP_SET_CONFIG(write_timeout);
        COR_HTTP_SET_CONFIG(keep_alive_timeout);

#undef COR_HTTP_SET_CONFIG
    }
}

static int
cor_http_listener_init(cor_http_t *ctx)
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) {
        cor_log_error(ctx->log, "can't socket, error: %d", errno);
        return cor_error;
    }
    int flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0 || fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
        cor_log_error(ctx->log, "can't fcntl, error: %d", errno);
        close(sd);
        return cor_error;
    }
    int reuse = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    struct linger ling = {0, 0};
    setsockopt(sd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    if (inet_aton(ctx->host, &addr.sin_addr) == 0) {
        cor_log_error(ctx->log, "can't inet_aton, error: %d", errno);
        close(sd);
        return cor_error;
    }
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        cor_log_error(ctx->log, "can't bind, error: %d", errno);
        close(sd);
        return cor_error;
    }
    if (listen(sd, ctx->config.backlog_size) == -1) {
        cor_log_error(ctx->log, "can't listen, error: %d", errno);
        close(sd);
        return cor_error;
    }
    /**/
    cor_http_request_t *r = cor_http_request_new(ctx);
    if (!r) {
        cor_log_error(ctx->log, "can't cor_http_request_new");
        close(sd);
        return cor_error;
    }
    r->sd = sd;
    ev_io_init(&r->ev, &cor_http_listen_cb, r->sd, EV_READ);
    r->ev.data = r;
    ev_io_start(ctx->loop, &r->ev);
    ctx->listen = r;

    return cor_ok;
}

static cor_http_request_t *
cor_http_request_new(cor_http_t *ctx)
{
    cor_http_request_t *r;
    if (ctx->free_requests) {
        r = ctx->free_requests;
        ctx->free_requests = r->next;
    } else {
        r =  (cor_http_request_t *) cor_list_append(ctx->requests);
        if (!r) {
            cor_log_error(ctx->log, "can't cor_list_append");
            return NULL;
        }
        r->pool = cor_pool_new(ctx->config.request_pool_size);
        if (!r->pool) {
            cor_log_error(ctx->log, "can't cor_pool_new");
            return NULL;
        }
    }
    cor_pool_t *pool = r->pool;
    memset(r, 0, sizeof(cor_http_request_t));
    r->ctx = ctx;
    r->pool = pool;
    cor_pool_reset(r->pool);
    /*  init events  */
    ev_init(&r->ev, &cor_http_request_ev_cb);
    r->ev.data = r;
    ev_init(&r->timer, &cor_http_request_timer_cb);
    r->timer.data = r;

    return r;
}

static void
cor_http_listen_cb(struct ev_loop *loop, ev_io *w, int ev_fl)
{
    cor_http_request_t *r = (cor_http_request_t *) w->data;
    cor_http_t *ctx = r->ctx;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    /**/
    while (1) {
        struct sockaddr_in addr;
        int sd = accept(r->sd, (struct sockaddr *) &addr, &addrlen);
        if (sd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            continue;
        }
        int flags = fcntl(sd, F_GETFL, 0);
        if (flags < 0) {
            cor_log_error(ctx->log, "can't fcntl");
            close(sd);
            continue;
        }
        if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
            cor_log_error(ctx->log, "can't fcntl");
            close(sd);
            continue;
        }
        cor_http_request_t *nr = cor_http_request_new(ctx);
        if (!nr) {
            cor_log_error(ctx->log, "can't cor_http_request_new");
            close(sd);
            break;
        }
        nr->sd = sd;
        nr->ip = ntohl(addr.sin_addr.s_addr);
        cor_http_request_set_conn_state(nr, COR_HTTP_READ);
        /*  start timer if timeout exists  */
        if (ctx->config.read_timeout) {
            ev_timer_set(&nr->timer, (double) ctx->config.read_timeout / 1000.0, 0.0);
            ev_timer_start(ctx->loop, &nr->timer);
        }
        cor_http_request_process(nr);
    }
}

static void
cor_http_request_ev_cb(struct ev_loop *loop, ev_io *w, int ev_fl)
{
    cor_http_request_t *r = (cor_http_request_t *) w->data;
    cor_http_t *ctx = r->ctx;
    ev_io_stop(ctx->loop, &r->ev);
    cor_http_request_process(r);
}

static void
cor_http_request_timer_cb(EV_P_ ev_timer *w, int ev_fl)
{
    cor_http_request_t *r = (cor_http_request_t *) w->data;
    cor_http_t *ctx = r->ctx;
    ev_timer_stop(ctx->loop, &r->timer);
    cor_http_request_close(r);
}

static void
cor_http_request_process(cor_http_request_t *r)
{
    while (1) {
        switch (r->conn_state) {
            case COR_HTTP_READ:
                /*  cor_ok in this place meen to continue fsm loop  */
                if (cor_http_request_read(r) != cor_ok) {
                    return;
                }
                break;
            case COR_HTTP_WRITE:
                if (cor_http_request_write(r) != cor_ok) {
                    return;
                }
                break;
            case COR_HTTP_WAIT:
                return;
            default:
                cor_http_request_close(r);
                return;
        }
    }
}

static int
cor_http_request_read(cor_http_request_t *r)
{
    cor_http_t *ctx = r->ctx;
    while (1) {
        cor_buf_t *b = r->read_bufs.tail;
        if (!b || b->last == b->end) {
            if (b && ctx->config.max_request_size && cor_buf_chain_size(&r->read_bufs) > ctx->config.max_request_size) {
                cor_log_warn(ctx->log, "max_request_size (%d) exceed", ctx->config.max_request_size);
                cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
                return cor_ok;
            }
            b = cor_buf_chain_append_buf(ctx->buf_pool, &r->read_bufs);
            if (!b) {
                cor_log_error(ctx->log, "can't cor_buf_chain_append_buf");
                cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
                return cor_ok;
            }
        }
        int rc = read(r->sd, b->last, b->end - b->last);
        if (rc > 0) {
            if (r->keep_alived) {
                /*  stop kepp-alive timeout timer  */
                r->keep_alived = 0;
                ev_timer_stop(ctx->loop, &r->timer);
                /*  set read timeout  */
                if (ctx->config.read_timeout) {
                    ev_timer_set(&r->timer, (double) ctx->config.read_timeout / 1000.0, 0.0);
                    ev_timer_start(ctx->loop, &r->timer);
                }
            }
            b->last += rc;
            rc = cor_http_parse(r);
            if (rc == cor_ok) {
                /*  request is full  */
                if (ev_is_active(&r->timer)) {
                    ev_timer_stop(ctx->loop, &r->timer);
                }
                /*  process request  */
                cor_http_after_parse(r);
                if (r->ctx->cb) {
                    r->dont_process_fsm = 1;
                    r->ctx->cb(r, r->ctx->arg);
                    r->dont_process_fsm = 0;
                } else {
                    /*  close connection if no callback defined  */
                    cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
                }
                cor_buf_chain_free(ctx->buf_pool, &r->read_bufs);
                return cor_ok;
            } else if (rc != COR_HTTP_PARSE_AGAIN) {
                /*  error while parsing request  */
#define COR_HTTP_SET_BODY(_s) cor_http_response_set_body(&res, _s, sizeof(_s) - 1);
                cor_http_response_t res;
                cor_http_response_init(&res, r);
                switch (rc) {
                    case COR_HTTP_PARSE_BAD_METHOD:
                    {
                        cor_http_response_set_code(&res, 501);
                        COR_HTTP_SET_BODY("method not implemented");
                        break;
                    }
                    case COR_HTTP_PARSE_BAD_REQUEST:
                    {
                        cor_http_response_set_code(&res, 400);
                        COR_HTTP_SET_BODY("bad request");
                        break;
                    }
                    default:
                    {
                        cor_http_response_set_code(&res, 500);
                        COR_HTTP_SET_BODY("error while request parsing");
                        break;
                    }
                }
#undef COR_HTTP_SET_BODY
                r->dont_process_fsm = 1;
                cor_http_response_send(&res);
                r->dont_process_fsm = 0;
                cor_buf_chain_free(ctx->buf_pool, &r->read_bufs);
                return cor_ok;
            }
        } else if (rc == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ev_io_set(&r->ev, r->sd, EV_READ);
                ev_io_start(ctx->loop, &r->ev);
                return cor_error;
            }
            cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
            return cor_ok;
        } else {
            cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
            return cor_ok;
        }
    }
}

static int
cor_http_request_write(cor_http_request_t *r)
{
    cor_http_t *ctx = r->ctx;
    while (1) {
        cor_buf_t *b = r->write_bufs.head;
        if (!b || b->bp == b->last) {
            /*  all writed  */
            if (ev_is_active(&r->timer)) {
                ev_timer_stop(ctx->loop, &r->timer);
            }
            if (r->keep_alive) {
                /*  reset request  */
                int keep_alive = r->keep_alive;
                cor_http_request_reset(r);
                /*  set keep-alive tiemout  */
                ev_timer_set(&r->timer, (double) keep_alive / 1000.0, 0.0);
                ev_timer_start(ctx->loop, &r->timer);
                r->keep_alived = 1;
                /*  go to read  */
                cor_http_request_set_conn_state(r, COR_HTTP_READ);
            } else {
                cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
            }
            if (b) {
                cor_buf_chain_free(ctx->buf_pool, &r->write_bufs);
            }
            return cor_ok;
        }
        int rc = write(r->sd, b->bp, b->last - b->bp);
        if (rc > 0) {
            b->bp += rc;
            if (b->bp == b->last) {
                cor_buf_chain_remove_head(ctx->buf_pool, &r->write_bufs);
            }
        } else if (rc == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ev_io_set(&r->ev, r->sd, EV_WRITE);
                ev_io_start(ctx->loop, &r->ev);
                return cor_error;
            }
            cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
            return cor_ok;
        } else {
            cor_http_request_set_conn_state(r, COR_HTTP_CLOSE);
            return cor_ok;
        }
    }
}

static void
cor_http_request_close(cor_http_request_t *r)
{
    cor_http_t *ctx = r->ctx;
    if (ev_is_active(&r->ev)) {
        ev_io_stop(ctx->loop, &r->ev);
    }
    if (ev_is_active(&r->timer)) {
        ev_timer_stop(ctx->loop, &r->timer);
    }
    if (r->sd != -1) {
        close(r->sd);
        r->sd = -1;
    }
    if (r->read_bufs.count) {
        cor_buf_chain_free(ctx->buf_pool, &r->read_bufs);
    }
    if (r->write_bufs.count) {
        cor_buf_chain_free(ctx->buf_pool, &r->write_bufs);
    }
    if (r->pool) {
        
    }
    r->next = ctx->free_requests;
    ctx->free_requests = r;
}

static void
cor_http_request_reset(cor_http_request_t *r)
{
    cor_http_t *ctx = r->ctx;
    /*  check if all data in read buffer used  */
    cor_buf_t *last_read_buf = NULL;
    if (r->read_bufs.tail) {
        cor_buf_t *b = r->read_bufs.tail;
        if (b->bp < b->last) {
            /*  not all data used, save last buffer  */
            last_read_buf = r->read_bufs.tail;
            /*  free all buffers before last  */
            while (r->read_bufs.head != r->read_bufs.tail) {
                cor_buf_chain_remove_head(ctx->buf_pool, &r->read_bufs);
            }
        }
    }
    /*  free write buffer  */
    if (r->write_bufs.count) {
        cor_buf_chain_free(ctx->buf_pool, &r->write_bufs);
    }
    /*  save some variables  */
    int sd = r->sd;
    uint32_t ip = r->ip;
    int keep_alive = r->keep_alive;
    cor_pool_t *pool = r->pool;
    /*  clear request  */
    memset(r, 0, sizeof(cor_http_request_t));
    /**/
    r->sd = sd;
    r->ip = ip;
    r->pool = pool;
    r->ctx = ctx;
    r->keep_alive = keep_alive;
    if (last_read_buf) {
        r->read_bufs.count = 1;
        r->read_bufs.head = r->read_bufs.tail = last_read_buf;
    }
    /*  init events  */
    ev_init(&r->ev, &cor_http_request_ev_cb);
    r->ev.data = r;
    ev_init(&r->timer, &cor_http_request_timer_cb);
    r->timer.data = r;
}

static inline void
cor_http_request_set_conn_state(cor_http_request_t *r, int state)
{
    r->conn_state = state;
}

static int
cor_http_parse(cor_http_request_t *r)
{
    // TODO учитывать, что нам может прийти несколько запросов подряд
    static uint32_t allowed[] = {
        0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */
                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x5fff3796, /* 0101 1111 1111 1111  0011 0111 1001 0110 */
                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };
    static uint8_t lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    enum {
        s_begin = 0,
        s_method,
        s_method_sp,
        s_schema,
        s_schema_slash,
        s_schema_slash_slash, //5
        s_host_begin,
        s_host,
        s_host_end,
        s_port,
        s_path, // 10
        s_uri_nl,
        s_param_begin,
        s_param,
        s_param_value_begin,
        s_param_value, // 15
        s_http,
        s_http_h,
        s_http_ht,
        s_http_htt,
        s_http_http, // 20
        s_http_ver_major,
        s_http_ver_minor,
        s_http_ver_space,
        s_header_begin,
        s_header, // 25
        s_header_nl,
        s_header_nl_nl,
        s_header_value_begin,
        s_header_value,
        s_before_host_space, // 30
        s_header_host,
        s_header_host_end,
        s_header_port,
        s_before_cookie_space,
        s_cookie,
        s_cookie_value_begin,
        s_cookie_value
    } state;
    state = r->parse_state;
    if (state == s_begin) {
        r->created = time(NULL);
    }
    char ch;
    unsigned int hash = r->hash;
    cor_log_t *log = r->ctx->log;
    for (cor_buf_t *b = r->read_bufs.tail; b; b = b->next) {
        char *p = b->bp;
        for (; p < b->last; ++p) {
            char c = *p;
            switch (state) {
                case s_begin:
                    r->begin = p;
                    if (c == '\n' || c == '\r') {
                        break;
                    }
                    if (c < 'A' || c > 'Z') {
                        cor_log_warn(log, "bad method");
                        return COR_HTTP_PARSE_BAD_METHOD;
                    }
                    state = s_method;
                    break;
                case s_method:
                    if (c == ' ') {
                        switch (p - r->begin) {
                            case 3:
                                if (strncmp(r->begin, "GET", 3) == 0) {
                                    r->method = COR_HTTP_GET;
                                } else if (strncmp(r->begin, "PUT", 3) == 0) {
                                    r->method = COR_HTTP_PUT;
                                }
                                break;
                            case 4:
                                if (strncmp(r->begin, "HEAD", 4) == 0) {
                                    r->method = COR_HTTP_HEAD;
                                } else if (strncmp(r->begin, "POST", 4) == 0) {
                                    r->method = COR_HTTP_POST;
                                }
                                break;
                            case 5:
                                if (strncmp(r->begin, "TRACE", 5) == 0) {
                                    r->method = COR_HTTP_TRACE;
                                }
                                break;
                            case 6:
                                if (strncmp(r->begin, "DELETE", 6) == 0) {
                                    r->method = COR_HTTP_DELETE;
                                }
                                break;
                            case 7:
                                if (strncmp(r->begin, "OPTIONS", 7) == 0) {
                                    r->method = COR_HTTP_OPTIONS;
                                }
                                break;
                        }
                        if (r->method == 0) {
                            cor_log_warn(log, "bad method");
                            return COR_HTTP_PARSE_BAD_METHOD;
                        }
                        state = s_method_sp;
                    } else if (c < 'A' || c > 'Z') {
                        cor_log_warn(log, "bad method");
                        return COR_HTTP_PARSE_BAD_METHOD;
                    }
                    break;
                case s_method_sp:
                    if (c == '/') {
                        r->path.data = p;
                        state = s_path;
                        break;
                    }
                    ch = c | 0x20;
                    if (ch >= 'a' && ch <= 'z') {
                        r->schema.data = p;
                        state = s_schema;
                        break;
                    }
                    if (c != ' ') {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_schema:
                    if (c == ':') {
                        r->schema.size = p - r->schema.data;
                        state = s_schema_slash;
                        break;
                    }
                    ch = c | 0x20;
                    if (ch < 'a' || ch > 'z') {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_schema_slash:
                    if (c == '/') {
                        state = s_schema_slash_slash;
                        break;
                    }
                    cor_log_warn(log, "bad request");
                    return COR_HTTP_PARSE_BAD_REQUEST;
                    break;
                case s_schema_slash_slash:
                    if (c == '/') {
                        state = s_host_begin;
                        break;
                    }
                    cor_log_warn(log, "bad request");
                    return COR_HTTP_PARSE_BAD_REQUEST;
                    break;
                case s_host_begin:
                    r->host.data = p;
                    state = s_host;
                    /*  next  */
                case s_host:
                    ch = c | 0x20;
                    if (ch >= 'a' && ch <= 'z') {
                        break;
                    }
                    if ((c >= '0' && c <= '9') || c == '.' || c == '-') {
                        break;
                    }
                case s_host_end:
                    r->host.size = p - r->host.data;
                    switch (c) {
                        case ':':
                            state = s_port;
                            break;
                        case '/':
                            r->path.data = p;
                            state = s_path;
                            break;
                        case ' ':
                            state = s_http;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_port:
                    if (c >= '0' && c <= '9') {
                        r->port = r->port * 10 + (c - '0');
                        break;
                    }
                    switch (c) {
                        case '/':
                            r->path.data = p;
                            state = s_path;
                            break;
                        case ' ':
                            state = s_http;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_path:
                    if (allowed[c >> 5] & (1 << (c & 0x1f)) || c == '/' || c == '.') {
                        break;
                    }
                    r->path.size = p - r->path.data;
                    switch (c) {
                        case ' ':
                            state = s_http;
                            break;
                        case '?':
                        case '&':
                            state = s_param_begin;
                            break;
                        case '\r':
                            state = s_uri_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_uri_nl:
                    if (c == '\n') {
                        state = s_header_begin;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_param_begin:
                    hash = 0;
                    r->key.data = p;
                    state = s_param;
                    /*  next  */
                case s_param:
                    if (allowed[c >> 5] & (1 << (c & 0x1f))) {
                        hash = cor_hash(hash, c);
                        break;
                    }
                    r->key.size = p - r->key.data;
                    switch (c) {
                        case '=':
                            state = s_param_value_begin;
                            break;
                        case '&':
                            state = s_param_begin;
                            break;
                        case ' ':
                            state = s_http;
                            break;
                        case '\r':
                            state = s_uri_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_param_value_begin:
                    r->value.data = p;
                    state = s_param_value;
                    /*  next  */
                case s_param_value:
                    if (allowed[c >> 5] & (1 << (c & 0x1f)) || c == '%' || c == '+' || c == '/' || c == '.') {
                        break;
                    }
                    r->value.size = p - r->value.data;
                    if (cor_http_parse_add_param(r, hash) != cor_ok) {
                        cor_log_warn(log, "can't cor_http_parse_add_param");
                        return cor_error;
                    }
                    switch (c) {
                        case '&':
                            state = s_param_begin;
                            break;
                        case ' ':
                            state = s_http;
                            break;
                        case '\r':
                            state = s_uri_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        case '#':
                            break;
                        default:
                            cor_log_warn(log, "bad request, %s", p);
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http:
                    switch (c) {
                        case ' ':
                            break;
                        case '\r':
                            r->http_minor = 9;
                            state = s_uri_nl;
                            break;
                        case '\n':
                            r->http_minor = 9;
                            state = s_header_begin;
                            break;
                        case 'H':
                            state = s_http_h;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_h:
                    if (c == 'T') {
                        state = s_http_ht;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_ht:
                    if (c == 'T') {
                        state = s_http_htt;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_htt:
                    if (c == 'P') {
                        state = s_http_http;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_http:
                    if (c == '/') {
                        state = s_http_ver_major;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_ver_major:
                    if (c >= '0' && c <= '9') {
                        r->http_major = r->http_major * 10 + (c - '0');
                        break;
                    }
                    if (c == '.') {
                        state = s_http_ver_minor;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_ver_minor:
                    if (c >= '0' && c <= '9') {
                        r->http_minor = r->http_minor * 10 + (c - '0');
                        break;
                    }
                    switch (c) {
                        case '\r':
                            state = s_uri_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        case ' ':
                            state = s_http_ver_space;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_http_ver_space:
                    switch (c) {
                        case ' ':
                            break;
                        case '\r':
                            state = s_uri_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_header_begin:
                    r->key.data = p;
                    switch (c) {
                        case '\r':
                            state = s_header_nl_nl;
                            break;
                        case '\n':
                            b->bp = p + 1;
                            return cor_ok;
                        default:
                            ch = lowcase[(uint8_t) c];
                            if (ch) {
                                p[0] = ch;
                                hash = cor_hash(0, ch);
                            }
                            state = s_header;
                            break;
                    }
                    break;
                case s_header:
                    ch = lowcase[(uint8_t) c];
                    if (ch) {
                        p[0] = ch;
                        hash = cor_hash(hash, ch);
                        break;
                    }
                    r->key.size = p - r->key.data;
                    switch (c) {
                        case ':':
                            switch (r->key.size) {
                                case 4:
                                    if (strncmp(r->key.data, "host", 4) == 0) {
                                        state = s_before_host_space;
                                    } else {
                                        state = s_header_value_begin;
                                    }
                                    break;
                                case 6:
                                    if (strncmp(r->key.data, "cookie", 6) == 0) {
                                        state = s_before_cookie_space;
                                    } else {
                                        state = s_header_value_begin;
                                    }
                                    break;
                                default:
                                    state = s_header_value_begin;
                                    break;
                            }
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_header_nl:
                    if (c == '\n') {
                        state = s_header_begin;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_header_nl_nl:
                    if (c == '\n') {
                        b->bp = p + 1;
                        return cor_ok;
                    } else {
                        cor_log_warn(log, "bad request");
                        return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_header_value_begin:
                    switch (c) {
                        case ' ':
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            r->value.data = p;
                            state = s_header_value;
                            break;
                    }
                    break;
                case s_header_value:
                    switch (c) {
                        case '\r':
                            r->value.size = p - r->value.data;
                            if (cor_http_parse_add_header(r, hash) != cor_ok) {
                                cor_log_warn(log, "can't cor_http_parse_add_header");
                                return cor_error;
                            }
                            state = s_header_nl;
                            break;
                        case '\n':
                            r->value.size = p - r->value.data;
                            if (cor_http_parse_add_header(r, hash) != cor_ok) {
                                cor_log_warn(log, "can't cor_http_parse_add_header");
                                return cor_error;
                            }
                            if (strncmp(r->key.data, "host", 4) == 0) {
                                r->host.data = r->value.data;
                                r->host.size = r->value.size;
                            }
                            state = s_header_begin;
                            break;
                    }
                    break;
                case s_before_host_space:
                    switch (c) {
                        case ' ':
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            r->host.data = p;
                            state = s_header_host;
                            break;
                    }
                    break;
                case s_header_host:
                    ch = c | 0x20;
                    if (ch >= 'a' && ch <= 'z') {
                        break;
                    }
                    if ((c >= '0' && c <= '9') || c == '.' || c == '-') {
                        break;
                    }
                case s_header_host_end:
                    r->host.size = p - r->host.data;
                    switch (c) {
                        case ':':
                            r->port = 0;
                            state = s_header_port;
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_header_port:
                    if (c >= '0' && c <= '9') {
                        r->port = r->port * 10 + (c - '0');
                        break;
                    }
                    switch (c) {
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            cor_log_warn(log, "bad request");
                            return COR_HTTP_PARSE_BAD_REQUEST;
                    }
                    break;
                case s_before_cookie_space:
                    switch (c) {
                        case ' ':
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            hash = cor_hash(0, c);
                            r->key.data = p;
                            state = s_cookie;
                            break;
                    }
                    break;
                case s_cookie:
                    switch (c) {
                        case '=':
                            r->key.size = p - r->key.data;
                            state = s_cookie_value_begin;
                            break;
                        case '\r':
                            state = s_header_nl;
                            break;
                        case '\n':
                            state = s_header_begin;
                            break;
                        default:
                            hash = cor_hash(hash, c);
                            break;
                    }
                    break;
                case s_cookie_value_begin:
                    r->value.data = p;
                    state = s_cookie_value;
                    /*  next  */
                case s_cookie_value:
                    switch (c) {
                        case ';':
                            r->value.size = p - r->value.data;
                            if (cor_http_parse_add_cookie(r, hash) != cor_ok) {
                                cor_log_warn(log, "can't cor_http_parse_add_cookie");
                                return cor_error;
                            }
                            state = s_before_cookie_space;
                            break;
                        case '\r':
                            r->value.size = p - r->value.data;
                            if (cor_http_parse_add_cookie(r, hash) != cor_ok) {
                                cor_log_warn(log, "can't cor_http_parse_add_cookie");
                                return cor_error;
                            }
                            state = s_header_nl;
                            break;
                        case '\n':
                            r->value.size = p - r->value.data;
                            if (cor_http_parse_add_cookie(r, hash) != cor_ok) {
                                cor_log_warn(log, "can't cor_http_parse_add_cookie");
                                return cor_error;
                            }
                            state = s_header_begin;
                            break;
                    }
                    break;
            }
        }
        b->bp = p;
    }
    r->parse_state = state;
    r->hash = hash;

    return COR_HTTP_PARSE_AGAIN;
}

static inline int
cor_http_parse_add_param(cor_http_request_t *r, unsigned int hash)
{
    if (r->key.size) {
        if (!r->params.elts) {
            if (cor_array_init(&r->params, r->pool, 1, sizeof(cor_http_param_t)) != cor_ok) {
                cor_log_error(r->ctx->log, "can't cor_array_init");
                return cor_error;
            }
        }
        cor_http_param_t *param = cor_array_push(&r->params);
        if (!param) {
            cor_log_error(r->ctx->log, "can't cor_array_push");
            return cor_error;
        }
        param->hash = hash;
        memcpy(&param->key, &r->key, sizeof(cor_str_t));
        if (r->value.size) {
            memcpy(&param->value, &r->value, sizeof(cor_str_t));
            param->value.size = cor_http_url_decode(param->value.data, param->value.size);
        } else {
            memset(&param->value, 0, sizeof(cor_str_t));
        }
    }

    return cor_ok;
}

static inline int
cor_http_parse_add_header(cor_http_request_t *r, unsigned int hash)
{
    if (r->key.size) {
        if (!r->headers.elts) {
            if (cor_array_init(&r->headers, r->pool, 1, sizeof(cor_http_header_t)) != cor_ok) {
                cor_log_error(r->ctx->log, "can't cor_array_init");
                return cor_error;
            }
        }
        cor_http_header_t *header = cor_array_push(&r->headers);
        if (!header) {
            cor_log_error(r->ctx->log, "can't cor_array_push");
            return cor_error;
        }
        header->hash = hash;
        memcpy(&header->key, &r->key, sizeof(cor_str_t));
        if (r->value.size) {
            memcpy(&header->value, &r->value, sizeof(cor_str_t));
        } else {
            memset(&header->value, 0, sizeof(cor_str_t));
        }
    }

    return cor_ok;
}

static inline int
cor_http_parse_add_cookie(cor_http_request_t *r, unsigned int hash)
{
    if (r->key.size) {
        if (!r->cookies.elts) {
            if (cor_array_init(&r->cookies, r->pool, 1, sizeof(cor_http_cookie_t)) != cor_ok) {
                cor_log_error(r->ctx->log, "can't cor_array_init");
                return cor_error;
            }
        }
        cor_http_cookie_t *cookie = cor_array_push(&r->cookies);
        if (!cookie) {
            cor_log_error(r->ctx->log, "can't cor_array_push");
            return cor_error;
        }
        memset(cookie, 0, sizeof(cor_http_cookie_t));
        /**/
        cookie->hash = hash;
        memcpy(&cookie->key, &r->key, sizeof(cor_str_t));
        if (r->value.size) {
            memcpy(&cookie->value, &r->value, sizeof(cor_str_t));
        }
    }

    return cor_ok;
}

static inline int
cor_http_url_decode(char *p, int size)
{
    enum {
        s_ord,
        s_quot,
        s_quot2
    } state;
    state = s_ord;
    char *begin = p;
    char *dst = p;
    char *end = p + size;
    char ch = 0, cl;
    for (; p < end; ++p) {
        char c = *p;
        switch (state) {
            case s_ord:
                if (c == '%') {
                    state = s_quot;
                    break;
                }
                *dst++ = c;
                break;
            case s_quot:
                if (c >= '0' && c <= '9') {
                    ch = c - '0';
                    state = s_quot2;
                    break;
                }
                cl = c | 0x20;
                if (cl >= 'a' && c <= 'f') {
                    ch = cl - 'a' + 10;
                    state = s_quot2;
                    break;
                }
                *dst++ = c;
                state = s_ord;
                break;
            case s_quot2:
                state = s_ord;
                if (c >= '0' && c <= '9') {
                    *((u_char *) dst++) = ((u_char) ch << 4) + (u_char) c - '0';
                    break;
                }
                cl = c | 0x20;
                if (cl >= 'a' && cl <= 'f') {
                    *((u_char *) dst++) = ((u_char) ch << 4) + (u_char) cl - 'a' + 10;
                    break;
                }
                break;
        }
    }

    return dst - begin;
}

static void
cor_http_after_parse(cor_http_request_t *r)
{
    /*  test for keep-alive  */
    cor_str_t *connection = cor_http_request_get_header(r, "connection", sizeof("connection") - 1);
    if (connection) {
        if (connection->size == sizeof("keep-alive") - 1) {
            /*  to lower  */
            for (int i = 0; i < connection->size; ++i) {
                connection->data[i] = cor_str_tolower(connection->data[i]);
            }
            if (strncmp(connection->data, "keep-alive", sizeof("keep-alive") - 1) == 0) {
                r->keep_alive = r->ctx->config.keep_alive_timeout;
            }
        }
    } else {
        if ((r->http_major * 1000 + r->http_minor) > 1000) {
            r->keep_alive = r->ctx->config.keep_alive_timeout;
        }
    }
}



