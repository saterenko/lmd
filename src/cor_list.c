#include "cor_list.h"

cor_list_t *
cor_list_new(int nelts, size_t size)
{
    cor_list_t *l = (cor_list_t *) malloc(sizeof(cor_list_t) + nelts * size);
    if (!l) {
        return NULL;
    }
    l->size = size;
    l->nelts = nelts;
    l->root.nelts = 0;
    l->root.elts = (char *) l + sizeof(cor_list_t);
    l->root.next = NULL;
    l->last = &l->root;

    return l;
}

void *
cor_list_append(cor_list_t *list)
{
    if (list->last->nelts == list->nelts) {
        cor_list_block_t *b = (cor_list_block_t *) malloc(sizeof(cor_list_block_t) + list->nelts * list->size);
        if (!b) {
            return NULL;
        }
        b->nelts = 0;
        b->next = NULL;
        b->elts = (char *) b + sizeof(cor_list_block_t);
        list->last->next = b;
        list->last = b;
    }
    void *el = (char *) list->last->elts + list->last->nelts * list->size;
    list->last->nelts++;

    return el;
}

void
cor_list_delete(cor_list_t *list)
{
    if (list) {
        if (list->root.next) {
            cor_list_block_t *b = list->root.next;
            cor_list_block_t *n = b->next;
            for (; ; b = n, n = n->next) {
                free(b);
                if (!n) {
                    break;
                }
            }
        }
        free(list);
    }
}

int
cor_list_nelts(cor_list_t *list)
{
    int nelts = 0;
    for (cor_list_block_t *b = &list->root; b; b = b->next) {
        nelts += b->nelts;
    }
    return nelts;
}
