#ifndef COR_ARRAY_H
#define COR_ARRAY_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "cor_core.h"
#include "cor_pool.h"

typedef struct
{
    void *elts;
    unsigned int nelts;
    unsigned int nalloc;
    size_t size;
    cor_pool_t *pool;
} cor_array_t;

cor_array_t *cor_array_new(cor_pool_t *pool, unsigned int n, size_t size);
void cor_array_delete(cor_array_t *a);
void *cor_array_push(cor_array_t *a);

static inline int
cor_array_init(cor_array_t *array, cor_pool_t *pool, unsigned int n, size_t size)
{
    array->nelts = 0;
    array->nalloc = n;
    array->size = size;
    array->pool = pool;
    array->elts = cor_pool_alloc(pool, n * size);
    if (!array->elts) {
        return cor_error;
    }

    return cor_ok;
}


#endif
