
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

//数组容器结构体,size of ()=20B
struct ngx_array_s {
	//数组的分配内存的起始地址，就是指针
    void        *elts;
	//数组实际包含的元素数量
    ngx_uint_t   nelts;
	//size 为单个元素的大小
    size_t       size;
	//为其分配的元素个数(容量)
    ngx_uint_t   nalloc;
	//应该是全局pool的指针
    ngx_pool_t  *pool;
};

// 创建一个新的数组容器
ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
// 销毁数组容器
void ngx_array_destroy(ngx_array_t *a);
// 将新的元素加入数组容器
void *ngx_array_push(ngx_array_t *a);

void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);


static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
	//pool point to the global pool
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
