
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void             *value;
    u_short           len;	//name的长度
    u_char            name[1];	//某个要hash的数据，即<key,value>的key
} ngx_hash_elt_t;


typedef struct {
    ngx_hash_elt_t  **buckets;	//hash桶(有size个桶)
    ngx_uint_t        size;	//hash桶的个数
} ngx_hash_t;


typedef struct {
    ngx_hash_t        hash;
    void             *value;
} ngx_hash_wildcard_t;

/*该结构也主要用来保存要hash的数据，即键-值对<key,value>，
在实际使用中，一般将多个键-值对保存在ngx_hash_key_t结构的数组中
，作为参数传给ngx_hash_init()或ngx_hash_wildcard_init()函数,16B
*/
typedef struct {
    ngx_str_t         key;			//key
    ngx_uint_t        key_hash;		//由此key计算出的hash值(使用hash函数如ngx_hash_key_lc())
    void             *value;		//该key对应的值,组成一个key,value
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    ngx_hash_t            hash;
    ngx_hash_wildcard_t  *wc_head;
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;

//用来将其相关数据封装起来作为参数传递给ngx_hash_init()或ngx_hash_wildcard_init()函数
//28B
typedef struct {
    ngx_hash_t       *hash;		//指向待初始化的hash结构
    ngx_hash_key_pt   key;		//hash函数指针

    ngx_uint_t        max_size;			//bucket的最大个数
    ngx_uint_t        bucket_size;		//每个bucket的空间

    char             *name;				//该hash结构的名字
    ngx_pool_t       *pool;				//该hash结构从pool指向的内存池中分配
    ngx_pool_t       *temp_pool;		//分配临时数据空间的内存池
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    ngx_uint_t        hsize;

    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

    ngx_array_t       keys;
    ngx_array_t      *keys_hash;

    ngx_array_t       dns_wc_head;
    ngx_array_t      *dns_wc_head_hash;

    ngx_array_t       dns_wc_tail;
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
//调用ngx_hash宏，该宏返回一个(长)整数
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
//lc=lower case,调用ngx_hash宏，该宏返回一个(长)整数
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
//调用ngx_hash宏，该宏返回一个(长)整数
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
