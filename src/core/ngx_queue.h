
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};

//��ʼ������
#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q

//�ж϶����Ƿ�Ϊ��
#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)

//��ͷ�ڵ�֮������½ڵ�
#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define ngx_queue_insert_after   ngx_queue_insert_head

//��β�ڵ�֮������½ڵ�
#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x

//
#define ngx_queue_head(h)                                                     \
    (h)->next


#define ngx_queue_last(h)                                                     \
    (h)->prev


#define ngx_queue_sentinel(h)                                                 \
    (h)


#define ngx_queue_next(q)                                                     \
    (q)->next


#define ngx_queue_prev(q)                                                     \
    (q)->prev


#if (NGX_DEBUG)
//ɾ���ڵ�x
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif

//�ָ����
//hΪ����ͷ(������ͷָ��)�����ö��д�q�ڵ㽫����(����)�ָ�Ϊ��������(����)��q֮��Ľڵ���ɵ��¶��е�ͷ�ڵ�Ϊn��
#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;

//���Ӷ���
#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;

//�ɶ��л����ṹ�����ϲ�����֪��
//nginx�Ķ��в���ֻ������ָ����м򵥵��޸�ָ�������
//��������ڵ����ݿռ�ķ��䡣��ˣ�
//�û���ʹ��nginx����ʱ��Ҫ�Լ��������ݽṹ������ռ䣬
//�������а���һ��ngx_queue_t��ָ����߶��󣬵���Ҫ��ȡ���нڵ�����ʱ��ʹ��ngx_queue_data��
#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))

//��ȡ���е��м�ڵ�
ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
//�������(�ȶ��Ĳ������)
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
