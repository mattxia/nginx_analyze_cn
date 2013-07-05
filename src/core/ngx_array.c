
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>

//创建数组
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

//在内存池上分配一个ngx_array_t结构体
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
//在内存池上分配空间
    a->elts = ngx_palloc(p, n * size);
    if (a->elts == NULL) {
        return NULL;
    }

    a->nelts = 0;
    a->size = size;
    a->nalloc = n;
    a->pool = p;

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

//将分配的内存收回
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }
//如果数组+结构体大小正好==d.last，就可以回收d.last移动位置
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

//向数组中添加元素实际上也是在修该内存池的last指针
//(若数组数据区满)及数组头信息，即使数组满了，
//需要扩展数据区内容，也只需要内存拷贝完成，
//并不需要数据的移动操作，这个效率也是相当高的
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

//每个item的size*实际分配的个数登陆整个占用的空间大小
        size = a->size * a->nalloc;

        p = a->pool;

//如果d的内存块上还有超过a->size的空间
        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */
//在当前的内存块上分配??这个数组的元素
            p->d.last += a->size;
//实际分配的数目加1
            a->nalloc++;

        } else {
            /* allocate a new array */
//否则重新分配2倍现有空间内存
            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }
//将a push到新生成的内存块上
            ngx_memcpy(new, a->elts, size);
//a的开始指针指向new
            a->elts = new;
//容量改成2
//注意：此处转移数据后，并未释放原来的数据区，内存池将统一释放

            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
	//实际分配数目+1
    a->nelts++;

    return elt;	//返回该末尾指针，即下一个元素应该存放的位置
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;
//实际分配数目如果大于容量，则创建移动数据
    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
