
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

//list�������ṹ��
struct ngx_list_part_s {
    void             *elts;	////ָ��ýڵ�ʵ�ʵ�������(���������п��Դ��nalloc����СΪsize��Ԫ��)
    ngx_uint_t        nelts;	//ʵ�ʴ�ŵ�Ԫ�ظ���
    ngx_list_part_t  *next;	//ָ����һ���ڵ�
};

//28B
typedef struct {
    ngx_list_part_t  *last;	////ָ���������һ���ڵ�(part)
    ngx_list_part_t   part;	//����ͷ�а����ĵ�һ���ڵ�(part)
    size_t            size;	//ÿ��Ԫ�ش�С
    ngx_uint_t        nalloc;	//���������ռ��������ʵ�ʷ����С�ռ�ĸ���
    ngx_pool_t       *pool;	//������ڵ�ռ��ڴ��ڴ���з���
} ngx_list_t;

//��������
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

//��ʼ������
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */

//�������Ԫ��
void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
