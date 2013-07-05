
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

//�ȴ���listͷ�ṹ��
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

//����list����ṹ��
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NULL;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
	//����Ϊn,����pushÿ�ζ���ô��
    list->nalloc = n;
    list->pool = pool;

    return list;
}

//����һ��Ԫ�ص�ָ��(λ��)������ʹ����
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

//ÿ�η���l->nalloc*l->size��,����last->nelts==l->nallocʱ��ʾ�Ѿ�����
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

//���뵽�б���ȥ
        l->last->next = last;
        l->last = last;
    }
//����Ԫ�ص�ָ��(λ��)
    elt = (char *) last->elts + l->size * last->nelts;
//��ǰ��list part��ʵ�ʴ��Ԫ�ظ�������1
    last->nelts++;

    return elt;
}
