#ifndef COR_LIST_H
#define COR_LIST_H

#include <stdlib.h>
#include <sys/types.h>

#include "cor_core.h"

typedef struct cor_list_block_s cor_list_block_t;
struct cor_list_block_s {
    int nelts;
    void *elts;
    cor_list_block_t *next;
};

typedef struct {
    int nelts;
    size_t size;
    cor_list_block_t root;
    cor_list_block_t *last;
} cor_list_t;

cor_list_t *cor_list_new(int nels, size_t size);
void *cor_list_append(cor_list_t *list);
void cor_list_delete(cor_list_t *list);
int cor_list_nelts(cor_list_t *list);

#endif
