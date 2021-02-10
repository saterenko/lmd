#ifndef COR_HTTP_H
#define COR_HTTP_H

#include <ev.h>

#include "cor_core.h"
#include "cor_array.h"
#include "cor_buf.h"
#include "cor_list.h"
#include "cor_log.h"
#include "cor_str.h"
#include "cor_pool.h"

#define COR_HTTP_COOKIE_EXPIRE_STR_SIZE sizeof("Wdy, DD-Mon-YYYY HH:MM:SS GMT") - 1

enum {
    COR_HTTP_DELETE = 1,
    COR_HTTP_GET,
    COR_HTTP_HEAD,
    COR_HTTP_OPTIONS,
    COR_HTTP_POST,
    COR_HTTP_PUT,
    COR_HTTP_TRACE
};

enum {
    COR_HTTP_PARSE_AGAIN = 1,
    COR_HTTP_PARSE_BAD_METHOD,
    COR_HTTP_PARSE_BAD_REQUEST
};

enum {
    COR_HTTP_CLOSE = 0,
    COR_HTTP_READ,
    COR_HTTP_WRITE,
    COR_HTTP_WAIT
};

typedef struct cor_http_s cor_http_t;
typedef struct cor_http_request_s cor_http_request_t;
typedef void (cor_http_cb_t) (cor_http_request_t *r, void *arg);

typedef struct
{
    unsigned int hash;
    cor_str_t key;
    cor_str_t value;
} cor_http_param_t;

typedef struct
{
    unsigned int hash;
    cor_str_t key;
    cor_str_t value;
} cor_http_header_t;

typedef struct
{
    unsigned int hash;
    unsigned int exp;
    cor_str_t key;
    cor_str_t value;
    cor_str_t domain;
    cor_str_t path;
} cor_http_cookie_t;

struct cor_http_request_s
{
    int sd;
    ev_io ev;
    ev_timer timer;
    int conn_state;
    time_t created;
    unsigned keep_alived:1;
    unsigned dont_process_fsm:1;
    /**/
    int parse_state;
    char *begin;
    unsigned int hash;
    cor_str_t key;
    cor_str_t value;
    /**/
    uint32_t ip;
    int method;
    int http_major;
    int http_minor;
    int port;
    int keep_alive;
    cor_str_t schema;
    cor_str_t host;
    cor_str_t path;
    cor_array_t params;
    cor_array_t headers;
    cor_array_t cookies;
    /**/
    cor_pool_t *pool;
    cor_buf_chain_t read_bufs;
    cor_buf_chain_t write_bufs;
    cor_http_t *ctx;
    cor_http_request_t *next;
};

typedef struct
{
    int code;
    const char *body;
    int body_size;
    cor_array_t headers;
    cor_array_t cookies;
    cor_http_request_t *request;
} cor_http_response_t;

typedef struct
{
    int backlog_size;
    int request_pool_size;
    int buf_count;
    int buf_size;
    int max_request_size;
    int read_timeout;
    int write_timeout;
    int keep_alive_timeout;
} cor_http_config_t;

struct cor_http_s
{
    int port;
    char *host;
    int backlog_size;
    cor_http_config_t config;
    time_t cookie_expires_timestamp;
    char cookie_expires_str[COR_HTTP_COOKIE_EXPIRE_STR_SIZE + 1];
    int cookie_expires_str_size;
    cor_http_cb_t *cb;
    void *arg;
    /**/
    cor_http_request_t *listen;
    cor_list_t *requests;
    cor_http_request_t *free_requests;
    cor_buf_pool_t *buf_pool;
    cor_pool_t *pool;
    cor_log_t *log;
    struct ev_loop *loop;
};

cor_http_t *cor_http_new(struct ev_loop *loop, const char *host, int port,
    cor_http_config_t *config, cor_log_t *log);
void cor_http_delete(cor_http_t *ctx);
int cor_http_start(cor_http_t *ctx, cor_http_cb_t *cb, void *arg);

cor_str_t *cor_http_request_get_param(cor_http_request_t *r, const char *key, int size);
cor_str_t *cor_http_request_get_header(cor_http_request_t *r, const char *key, int size);
cor_str_t *cor_http_request_get_cookie(cor_http_request_t *r, const char *key, int size);

cor_http_response_t *cor_http_response_new(cor_http_request_t *request);
void cor_http_response_init(cor_http_response_t *r, cor_http_request_t *request);
void cor_http_response_set_code(cor_http_response_t *r, int code);
void cor_http_response_set_body(cor_http_response_t *r, const char *data, int size);
int cor_http_response_add_header(cor_http_response_t *r, cor_http_header_t *header);
int cor_http_response_add_cookie(cor_http_response_t *r, cor_http_cookie_t *cookie);
int cor_http_response_send(cor_http_response_t *r);

#endif
