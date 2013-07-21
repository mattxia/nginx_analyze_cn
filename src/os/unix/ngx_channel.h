
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/*
在Nginx中它仅仅是用着master发送指令给worker的一个管道，
master借此channel来告诉worker进程该做什么了，
worker却不需要告诉master该做什么，所以是一个单向的通道
*/

typedef struct {
     ngx_uint_t  command;	//命令字
     ngx_pid_t   pid;		//进程 IDworker进程的pid
     ngx_int_t   slot;		//worker进程的slot（在ngx_proecsses中的索引）
     ngx_fd_t    fd;		//一个文件描述符,master进程可能会将一个打开的文件描述符发送给worker进程进行读写操作，那么此时就需要填写fd这个字段
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
