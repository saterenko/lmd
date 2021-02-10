#include "cor_buf.h"

cor_buf_pool_t *
cor_buf_pool_new(int nels, size_t size)
{
    cor_buf_pool_t *bp = (cor_buf_pool_t *) malloc(sizeof(cor_buf_pool_t));
    if (!bp) {
        return NULL;
    }
    memset(bp, 0, sizeof(cor_buf_pool_t));
    bp->bufs = cor_list_new(nels, size + sizeof(cor_buf_t));
    if (!bp->bufs) {
        free(bp);
        return NULL;
    }

    return bp;
}

void
cor_buf_pool_delete(cor_buf_pool_t *bp)
{
    if (bp) {
        if (bp->bufs) {
            cor_list_delete(bp->bufs);
        }
        free(bp);
    }
}

cor_buf_t *
cor_buf_new(cor_buf_pool_t *bp)
{
    cor_buf_t *b;
    if (bp->free_bufs) {
        b = bp->free_bufs;
        bp->free_bufs = b->next;
    } else {
        b = (cor_buf_t *) cor_list_append(bp->bufs);
        if (!b) {
            return NULL;
        }
        b->begin = (char *) b + sizeof(cor_buf_t);
        b->end = (char *) b + bp->bufs->size;
    }
    b->bp = b->last = b->begin;
    b->next = NULL;

    return b;
}

void
cor_buf_free(cor_buf_pool_t *bp, cor_buf_t *b)
{
    b->next = bp->free_bufs;
    bp->free_bufs = b;
}

void
cor_buf_chain_free(cor_buf_pool_t *bp, cor_buf_chain_t *bc)
{
    cor_buf_t *b = bc->head;
    cor_buf_t *n = bc->head->next;
    for (; ; b = n, n = n->next) {
        cor_buf_free(bp, b);
        if (!n) {
            break;
        }
    }
    memset(bc, 0, sizeof(cor_buf_chain_t));
}

int
cor_buf_chain_size(cor_buf_chain_t *bc)
{
    int size = 0;
    for (cor_buf_t *b = bc->head; b; b = b->next) {
        size += b->last - b->begin;
    }

    return size;
}

cor_buf_t *
cor_buf_chain_append_buf(cor_buf_pool_t *bp, cor_buf_chain_t *bc)
{
    cor_buf_t *b = cor_buf_new(bp);
    if (!b) {
        return NULL;
    }
    if (bc->tail) {
        bc->tail->next = b;
        bc->tail = b;
    } else {
        bc->head = bc->tail = b;
    }
    bc->count++;

    return b;
}

int
cor_buf_chain_append_data(cor_buf_pool_t *bp, cor_buf_chain_t *bc, const char *data, size_t size)
{
    cor_buf_t *b = bc->tail;
    if (!b) {
        b = cor_buf_chain_append_buf(bp, bc);
        if (!b) {
            return cor_error;
        }
    }
    while (size) {
        if (b->last == b->end) {
            b = cor_buf_chain_append_buf(bp, bc);
            if (!b) {
                return cor_error;
            }
        }
        if (size > b->end - b->last) {
            memcpy(b->last, data, b->end - b->last);
            b->last = b->end;
            size -= b->end - b->last;
        } else {
            memcpy(b->last, data, size);
            b->last += size;
            break;
        }
    }

    return cor_ok;
}

void
cor_buf_chain_remove_head(cor_buf_pool_t *bp, cor_buf_chain_t *bc)
{
    cor_buf_t *b = bc->head;
    if (b) {
        bc->head = b->next;
        bc->count--;
        if (!bc->head) {
            bc->tail = NULL;
        }
        cor_buf_free(bp, b);
    }
}

