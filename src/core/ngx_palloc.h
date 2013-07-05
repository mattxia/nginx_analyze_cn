
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
 //ÔÚx86ÌåÏµ½á¹¹ÏÂ£¬¸ÃÖµÒ»°ãÎª4096B,¼´4K
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)

//clean upµÄº¯ÊıÖ¸Õë
typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

//clean upµÄpool
struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;
    void                 *data;
    ngx_pool_cleanup_t   *next;
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

//´ó¿éÄÚ´æ
struct ngx_pool_large_s {
    ngx_pool_large_t     *next;		//Ö¸ÏòÏÂÒ»¸ö´ó¿éÄÚ´æ
    void                 *alloc;	//Ö¸Ïò·ÖÅäµÄ´ó¿éÄÚ´æ
};

//ÄÚ´æ³ØÊı¾İ¿é,16B
typedef struct {
    u_char               *last;	 //µ±Ç°ÄÚ´æ³Ø·ÖÅäµ½´Ë´¦£¬¼´ÏÂÒ»´Î·ÖÅä´Ó´Ë´¦¿ªÊ¼
    u_char               *end;	//ÄÚ´æ³Ø½áÊøÎ»ÖÃ
    ngx_pool_t           *next;	//ÄÚ´æ³ØÀïÃæÓĞºÜ¶à¿éÄÚ´æ£¬ÕâĞ©ÄÚ´æ¿é¾ÍÊÇÍ¨¹ı¸ÃÖ¸ÕëÁ¬³ÉÁ´±íµÄ
    ngx_uint_t            failed;	//ÄÚ´æ³Ø·ÖÅäÊ§°Ü´ÎÊı
} ngx_pool_data_t;

//ÄÚ´æ³ØÍ·²¿½á¹¹Ìå,40B
struct ngx_pool_s {
    ngx_pool_data_t       d;	//ÄÚ´æ³ØµÄÊı¾İ¿é(poolµÄµÚÒ»¸öÄÚ´æ¿é)
    size_t                max;	//ÄÚ´æ³ØÊı¾İ¿éµÄ×î´óÖµ,Êı¾İ¿é´óĞ¡£¬¼´Ğ¡ÄÚ´æµÄ×î´óÖµ
    ngx_pool_t           *current;	//Ö¸Ïòµ±Ç°ÄÚ´æ³Ø£¬Ó¦¸ÃÊÇÄÚ´æ³ØÍ·å
    ngx_chain_t          *chain;	//¸ÃÖ¸Õë¹Ò½ÓÒ»¸öngx_chain_t½á¹¹????
    ngx_pool_large_t     *large;	//´ó¿éÄÚ´æÁ´±í£¬¼´·ÖÅä¿Õ¼ä³¬¹ımaxµÄÄÚ´æ
    ngx_pool_cleanup_t   *cleanup;	//ÊÍ·ÅÄÚ´æ³ØµÄcallback
    ngx_log_t            *log;		//ÈÕÖ¾ĞÅÏ¢
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
