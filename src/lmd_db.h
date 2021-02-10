#ifndef LMD_DB_H
#define LMD_DB_H

#include <inttypes.h>

typedef struct lmd_db_s lmd_db_el_t;

struct lmd_db_el_s
{
    const char *key;
    int key_size;
    lmd_db_el_t *els;
};

typedef struct
{
    
} lmd_db_t;

lmd_db_t *lmd_db_new();
void lmd_db_delete(lmd_db_t *db);
void lmd_db_set(lmd_db_t *db, const char *key, int key_size, int64_t value);


#endif
