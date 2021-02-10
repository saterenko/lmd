# lmd

Демон для контроля ограничений

## Клиент

Методы:

* void lmd_limit_set(const char *key, size_t key_size, int64_t limit)
* int64_t lmd_limit_get(const char *key, size_t key_size)
* void lmd_value_set(const char *key, size_t key_size, int64_t value)
* int64_t lmd_value_get(const char *key, size_t key_size)
* uint64_t lmd_value_lock(const char *key, size_t key_size, int64_t value)
* uint64_t lmd_value_commit(const char *key, size_t key_size, uint64_t transaction_id)
* uint64_t lmd_value_rollback(const char *key, size_t key_size, uint64_t transaction_id)

## HTTP

/[key_1]/[key_2]/../[key_N]/[method]?[param_name_1]=[param_value_1]..

Методы:

* set-limits 
```
{
    key: "[part1].[part2]...[partN]",
    limit: [limit],
    childs: {
        key: "[partN+1].[partN+2]...[partN+M]",
        limit: [limit] 
    } 
}
```
* get-limits

[comment]: <> (* set_limit -- установить огранчиений)

[comment]: <> (* get_limit -- получить ограничений)

[comment]: <> (* set_value -- установить значение)

[comment]: <> (* get_value -- получить значение)

[comment]: <> (* lock_value -- зарезервировать некоторое количество от значения )

[comment]: <> (* commit_value -- подтвердить зарезервированное значение)

[comment]: <> (* rollback_value -- откатить зарезервированное значение)

[comment]: <> (* register_client -- зарегистрировать клиент)

[comment]: <> (* unregister_client -- снаять регистрацию клиента)

[comment]: <> (* sync_client -- синхронизировать значения )