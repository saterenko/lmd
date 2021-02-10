#include "cor_str.h"

cor_str_t *cor_str_new(cor_pool_t *pool, size_t size)
{
    cor_str_t *str;
    if (pool) {
        str = (cor_str_t *) cor_pool_alloc(pool, sizeof(cor_str_t) + size + 1);
        if (!str) {
            return NULL;
        }
    } else {
        str = (cor_str_t *) malloc(sizeof(cor_str_t) + size + 1);
        if (!str) {
            return NULL;
        }
    }
    str->data = (char *) str + sizeof(cor_str_t);
    str->size = 0;
    str->data[0] = '\0';

    return str;
}

cor_str_t *
cor_str_make_from_charptr(cor_pool_t *pool, const char *src, size_t size)
{
    cor_str_t *str;
    if (pool) {
        str = (cor_str_t *) cor_pool_alloc(pool, sizeof(cor_str_t) + size + 1);
        if (!str) {
            return NULL;
        }
    } else {
        str = (cor_str_t *) malloc(sizeof(cor_str_t) + size + 1);
        if (!str) {
            return NULL;
        }
    }
    str->data = (char *) str + sizeof(cor_str_t);
    str->size = size;
    memcpy(str->data, src, str->size);
    str->data[str->size] = '\0';

    return str;
}

void
cor_str_utf8_to_lower(char *src, int size)
{
    uint8_t *p = (uint8_t *) src;
    uint8_t *end = p + size;
    for (; p < end; ++p) {
        if (p[0] & 0x80) {
            if (p[0] == 0xd0) {
                if (p[1] >= 0x90) {
                    if (p[1] <= 0x9f) {
                        /*  А-П -> а-п  */
                        p[1] = p[1] + 0x20;
                    } else if (p[1] <= 0xaf) {
                        /*  Р-Я -> р-я  */
                        p[0] = 0xd1;
                        p[1] = p[1] - 0x20;
                    }
                } else if (p[1] == 0x81) {
                    /*  Ё -> е  */
                    p[1] = 0xb5;
                } else if (p[1] >= 0x80 && p[1] <= 0x8f) {
                    /*  кириллические загогулины  */
                    p[0] = 0xd1;
                    p[1] = p[1] + 0x10;
                }
                ++p;
            } else if (p[0] == 0xd1 && p[1] == 0x91) {
                /*  ё -> е  */
                p[0] = 0xd0;
                p[1] = 0xb5;
                ++p;
            } else if (p[0] == 0xd2) {
                /*  кириллические загогулины  */
                if (p[1] >= 0x8a && p[1] <= 0xbf) {
                    p[1] = p[1] | 0x1;
                }
                ++p;
            }
        } else {
            if (p[0] >= 'A' && p[0] <= 'Z') {
                p[0] =  p[0] | 0x20;
            }
        }
    }
}

int
cor_str_itoa(int n, char *buf)
{
    char *k = buf;
    int i = n;
    do {
        ++k;
    } while (i /= 10);
    int size = k - buf;
    do {
        (*--k) = n % 10 + '0';
    } while (n /= 10);

    return size;
}

