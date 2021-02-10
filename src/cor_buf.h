#ifndef COR_BUF_H
#define COR_BUF_H

#include <stdlib.h>
#include <string.h>

#include "cor_core.h"
#include "cor_list.h"

typedef struct cor_buf_s cor_buf_t;
struct cor_buf_s
{
    char *begin;
    char *end;
    char *bp;
    char *last;
    cor_buf_t *next;
};

typedef struct
{
    int count;
    cor_buf_t *head;
    cor_buf_t *tail;
} cor_buf_chain_t;

typedef struct
{
    cor_list_t  *bufs;
    cor_buf_t   *free_bufs;
} cor_buf_pool_t;

cor_buf_pool_t *cor_buf_pool_new(int nels, size_t size);
void cor_buf_pool_delete(cor_buf_pool_t *bp);
cor_buf_t *cor_buf_new(cor_buf_pool_t *bp);
void cor_buf_free(cor_buf_pool_t *bp, cor_buf_t *b);
void cor_buf_chain_free(cor_buf_pool_t *bp, cor_buf_chain_t *bc);
int cor_buf_chain_size(cor_buf_chain_t *bc);
cor_buf_t *cor_buf_chain_append_buf(cor_buf_pool_t *bp, cor_buf_chain_t *bc);
int cor_buf_chain_append_data(cor_buf_pool_t *bp, cor_buf_chain_t *bc, const char *data, size_t size);
void cor_buf_chain_remove_head(cor_buf_pool_t *bp, cor_buf_chain_t *bc);

#endif
