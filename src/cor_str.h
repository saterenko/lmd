#ifndef COR_STR_H
#define COR_STR_H

#include "cor_pool.h"

typedef struct
{
    size_t size;
    char *data;
} cor_str_t;

#define cor_str(_s) { sizeof(_s) - 1, _s }
#define cor_str_null  { 0, NULL }
#define cor_str_tolower(_c) (_c >= 'A' && _c <= 'Z') ? (_c | 0x20) : _c
#define cor_str_toupper(_c) (_c >= 'a' && _c <= 'z') ? (_c & ~0x20) : _c

cor_str_t *cor_str_new(cor_pool_t *pool, size_t size);
cor_str_t *cor_str_make_from_charptr(cor_pool_t *pool, const char *src, size_t size);
void cor_str_utf8_to_lower(char *src, int size);
int cor_str_itoa(int n, char *buf);

static inline void cor_str_fill_from_charptr(cor_str_t *str, const char *src, size_t size)
{
    memcpy(str->data, src, size + 1);
    str->data[size] = '\0';
    str->size = size;
}

#endif
