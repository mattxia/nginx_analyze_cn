
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

//先创建list头结构体
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

//创建list链表结构体
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NULL;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
	//容量为n,后续push每次都这么大
    list->nalloc = n;
    list->pool = pool;

    return list;
}

//分配一个元素的指针(位置)给最终使用者
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

//每次分配l->nalloc*l->size个,所以last->nelts==l->nalloc时表示已经满了
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

//加入到列表当中去
        l->last->next = last;
        l->last = last;
    }
//返回元素的指针(位置)
    elt = (char *) last->elts + l->size * last->nelts;
//当前的list part的实际存放元素个数增加1
    last->nelts++;

    return elt;
}
