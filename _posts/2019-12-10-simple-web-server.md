---
layout: post
title: "[code] 实现简易高并发Web server"
---

源代码：https://github.com/pench3r/Program-Study/tree/master/c/webserver

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

