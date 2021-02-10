#include "cor_pool.h"

static inline void *cor_pool_alloc_small(cor_pool_t *pool, size_t size);
static inline void *cor_pool_alloc_large(cor_pool_t *pool, size_t size);

cor_pool_t *
cor_pool_new(size_t size)
{
    cor_pool_t *p = (cor_pool_t *) malloc(size);
    if (!p) {
        return NULL;
    }
    p->last = (uint8_t *) p + sizeof(cor_pool_t);
    p->end = (uint8_t *) p + size;
    p->cur = p;
    p->next = NULL;
    p->large = NULL;
    p->size = (size > COR_POOL_ALLOC_MAX) ? COR_POOL_ALLOC_MAX : size;
    p->failed = 0;

    return p;
}

void
cor_pool_reset(cor_pool_t *pool)
{
    cor_pool_t *p, *n;
    for (p = pool, n = pool->next; ; p = n, n = n->next) {
        p->last = (uint8_t *) p + sizeof(cor_pool_t);
        p->failed = 0;
        if (!n) {
            break;
        }
    }
    pool->cur = pool;
    cor_pool_large_t *l;
    for (l = pool->large; l; l = l->next) {
        if (l->data) {
            free(l->data);
        }
    }
    pool->large = NULL;
}

size_t cor_pool_allocated_size(cor_pool_t *pool)
{
    size_t size = 0;
    cor_pool_t *p, *n;
    for (p = pool, n = pool->next; ; p = n, n = n->next) {
        size += p->end - (uint8_t *) p;
        if (!n) {
            break;
        }
    }
    return size;
}

void *
cor_pool_alloc(cor_pool_t *pool, size_t size)
{
    if (size <= pool->size) {
        cor_pool_t *p = pool->cur;
        do {
            uint8_t *m = (uint8_t *) cor_align_ptr(p->last);
            if ((p->end - m) >= size) {
                p->last = m + size;
                return m;
            }
            p = p->next;
        } while (p);
        return cor_pool_alloc_small(pool, size);
    }
    return cor_pool_alloc_large(pool, size);
}

void *
cor_pool_calloc(cor_pool_t *pool, size_t size)
{
    void *m = cor_pool_alloc(pool, size);
    if (m) {
        memset(m, 0, size);
    }

    return m;
}

void
cor_pool_free(cor_pool_t *pool, void *m)
{
    cor_pool_large_t *l;
    for (l = pool->large; l; l = l->next) {
        if (m == l->data) {
            free(l->data);
            l->data = NULL;
            return;
        }
    }
}

void
cor_pool_delete(cor_pool_t *pool)
{
    if (pool) {
        for (cor_pool_large_t *l = pool->large; l; l = l->next) {
            if (l->data) {
                free(l->data);
            }
        }
        cor_pool_t *p, *n;
        for (p = pool, n = pool->next; ; p = n, n = n->next) {
            free(p);
            if (!n) {
                break;
            }
        }
    }
}

static void *
cor_pool_alloc_small(cor_pool_t *pool, size_t size)
{
    size_t psize = pool->end - (uint8_t *) pool;
    cor_pool_t *np = (cor_pool_t *) malloc(psize);
    if (!np) {
        return NULL;
    }
    uint8_t *m = (uint8_t *) np + sizeof(cor_pool_t);
    m = (uint8_t *) cor_align_ptr(m);
    np->last = m + size;
    np->end = (uint8_t *) np + psize;
    np->next = NULL;
    np->failed = 0;
    cor_pool_t *c = pool->cur;
    cor_pool_t *p = c;
    for (; p->next; p = p->next) {
        if (p->failed++ > 4) {
            c = p->next;
        }
    }
    p->next = np;
    pool->cur = c ? c : np;

    return m;
}

static void *
cor_pool_alloc_large(cor_pool_t *pool, size_t size)
{
    void *m = malloc(size);
    if (!m) {
        return NULL;
    }
    cor_pool_large_t *l = cor_pool_alloc(pool, sizeof(cor_pool_large_t));
    if (!l) {
        free(m);
        return NULL;
    }
    l->data = m;
    l->next = pool->large;
    pool->large = l;

    return m;
}


