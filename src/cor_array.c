#include "cor_array.h"

cor_array_t *
cor_array_new(cor_pool_t *pool, unsigned int n, size_t size)
{
    cor_array_t *a = cor_pool_alloc(pool, sizeof(cor_array_t));
    if (!a) {
        return NULL;
    }
    if (cor_array_init(a, pool, n, size) != cor_ok) {
        return NULL;
    }

    return a;
}

void
cor_array_delete(cor_array_t *a)
{
    cor_pool_t *p = a->pool->cur;
    size_t size = a->nelts * a->size;
    if ((uint8_t *) a->elts + size == p->last) {
        p->last -= size;
    }
    if ((uint8_t *) a + sizeof(cor_array_t) == p->last) {
        p->last = (uint8_t *) a;
    }
}

void *
cor_array_push(cor_array_t *a)
{
    if (a->nelts == a->nalloc) {
        cor_pool_t *p = a->pool->cur;
        size_t size = a->nelts * a->size;
        if ((uint8_t *) a->elts + size == p->last && p->last + a->size <= p->end) {
            p->last += a->size;
            a->nalloc++;
        } else {
            void *new = cor_pool_alloc(a->pool, size * 2);
            if (!new) {
                return NULL;
            }
            memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }
    void *el = (uint8_t *) a->elts + a->nelts * a->size;
    ++a->nelts;

    return el;
}


