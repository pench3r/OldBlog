---
layout: post
title: "[code] 实现简易高并发Web server"
categories: "Coding"
---

源代码：https://github.com/pench3r/Program-Study/tree/master/c/webserver

两部分：

* 自己实现的web server
* tinyhttpd源码分析

#### 关键功能拆分：

* server socket监听、接收client连接、获取client发送的数据、回复client响应数据
* 使用线程池处理连接进来的多个client
* 使用non-blocking epoll来处理高并发
* 利用有限状态机来解析http协议

#### 线程池

创建固定数量的线程，统一task的格式，主进程通过线程池中的链表添加task，线程池中的子进程都从共享的链表中获取task，并执行

实现关键点：

* 对于共享task链表访问操作，主进程通过获取锁再进行task链表的增加操作，添加完毕后使用pthread_cond_signal去唤醒至少一个阻塞的子进程；

* 子进程都会针对task链表进行删除操作，先获取对应的锁，当链表为空时，则使用pthread_cond_wait阻塞进程，等待主进程添加新的任务，该api会进行如下操作：

  ```
  解锁互斥量mutex
  阻塞线程，直到另一线程就条件变量cond发出信号
  重新锁定mutex
  ```

  这样的方式避免了子进程的死锁情况，例如子进程获取到了锁但是链表一直为空，主进程又无法获取到锁添加任务，导致死循环

API:

```
#include <pthread.h>

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_cond_init(pthread_cond_t *restrict cond, const pthread_condattr_t *restrict attr);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);

```

#### NON-Block Epoll

将listen_socket、client_socket都通过fcntl设置为O_NONBLOCK，并且都注册为EPOLLIN | EPOLLET事件，再通过epoll_wait进行统一处理

实现的关键点：

* 触发的事件的fd如果是listen socket，则将连接进来的socket处理添加至epoll中
* 对于client socket接收的数据循环处理，只有当接收的返回值为0时，表明客户端断开了连接；当接收的返回值为-1，并且errno为EAGAIN时表明为长连接，保留fd继续监听事件
* 接收的事件类型为：EPOLLERR、EPOLLHUP、非EPOLLIN时，关闭对应的fd
* event.data.ptr可以传递自定义的参数信息，这样可以在事件处理时更方便保存请求信息

API：

```
#include <sys/epoll.h>

int epoll_create1(int flag);	// 一般都为0
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int epoll_wait(int epfd, struct epoll_event *evlist, int maxevents, int timeout);
struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

#include <unistd.h>
#include <fcntl.h>
int fcntl(int fd, int cmd, ... /* arg */ );
```

#### HTTP协议解析

* 接收数据
* 解析请求头部
* 解析请求体

使用有限状态机针对请求头的第一个行处理和剩余请求头处理

协议的解析涉及很多约定，因此通过添加多个状态完善状态机的解析功能

解析的uri、header都是通过指针配合长度来定位

通过chroot来限定根目录，防止跨目录，需要root权限

文件的读取，可以通过mmap映射到内存中，直接写入socket中；避免从磁盘再次读取整个文件，再写入到socket中

#### Tinyhttpd源码分析

主体框架使用主进程接收连接，再通过创建对应的线程处理http请求，接收固定字节的请求后，依次保存解析到的method、url、query_string；判断接受文件类型，分别处理静态文件和cgi文件

##### 解析http协议的过程

使用get_line函数获取固定字节的数据到buf中，返回接收的字节数

```c
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;
    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}
```

遍历数据保存非空格的数据至255字节大小的空间中，该空间名称为method

```c
while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
{
    method[i] = buf[i];
    i++;
}
```

校验method是否为GET或者POST

继续遍历非空格的数据，保存至255字节大小的空间中，该空间名称为url

```c
while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
{
    url[i] = buf[j];
    i++; j++;
}
url[i] = '\0';
```

如果请求为GET，解析querystring数据

```c
if (strcasecmp(method, "GET") == 0)
{
    query_string = url;
    while ((*query_string != '?') && (*query_string != '\0'))
        query_string++;
    if (*query_string == '?')
    {
        cgi = 1;
        *query_string = '\0';
        query_string++;
    }
}
```

##### 处理静态文件

直接通过fgets批量读取文件内容写入socket中

```
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}
```

##### 处理CGI文件

对于GET请求，丢弃所有header信息

```
buf[0] = 'A'; buf[1] = '\0';
if (strcasecmp(method, "GET") == 0)
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));
```

对于POST请求，通过header Content-Length获取post中的内容，其他header都丢弃

初始化2个管道，cgi_out和cgi_input，接着开启子进程执行cgi文件，子进程将stdin和stdout绑定到之前初始化的管道

```c
dup2(cgi_output[1], STDOUT);	// 管道的写端与子进程的输出绑定在一起
dup2(cgi_input[0], STDIN);		// 管道的读端与子进程的输入绑定在一起
close(cgi_output[0]);
close(cgi_input[1]);
```

通过环境变量传入参数，再配合execl去执行最后的cgi程序

```c
sprintf(meth_env, "REQUEST_METHOD=%s", method);
putenv(meth_env);
if (strcasecmp(method, "GET") == 0) {
    sprintf(query_env, "QUERY_STRING=%s", query_string);
    putenv(query_env);
}
else {   /* POST */
    sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
    putenv(length_env);
}
execl(path, NULL);
```

父进程中：通过管道传递post的内容、通过管道读取cgi脚本执行的输出结果并回传给客户端：

传递post内容：

```
if (strcasecmp(method, "POST") == 0)
    for (i = 0; i < content_length; i++) {
        recv(client, &c, 1, 0);
        write(cgi_input[1], &c, 1);
    }
```

读取输出结果，并通过socket回传给客户端：

```
while (read(cgi_output[0], &c, 1) > 0)
    send(client, &c, 1, 0);
```

