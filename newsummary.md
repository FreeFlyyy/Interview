
# 面试复习总结

<!-- TOC -->

- [面试复习总结](#面试复习总结)
    - [安全](#安全)
    - [http](#http)
    - [Linux-CPU](#linux-cpu)
    - [Linux-Memory](#linux-memory)
    - [Linux-Network](#linux-network)
    - [Redis](#redis)
    - [MySQL](#mysql)
    - [Nginx & Openresty](#nginx--openresty)
    - [OAuth2.0](#oauth20)
    - [OIDC](#oidc)
    - [C++](#c)
    - [容器化技术](#容器化技术)
    - [分布式相关](#分布式相关)
    - [Celery](#celery)
    - [Python](#python)
    - [LUA](#lua)
    - [项目流程图](#项目流程图)

<!-- /TOC -->
## 安全
* XSS，跨脚本攻击。主要是在页面中注入了恶意代码。
* CSRF，跨站点攻击，主要是用户自动发起请求时带上了登录态。

## http
* cache-control
    * no-store，强制要求浏览器不进行缓存。
    * no-cache, 强制要求把数据标识发给服务器进行校验，如果没有变化响应304。
    * private/public，主要是告诉代理服务器或者cdn的，private由用户缓存，public随意缓存。
    * max-age，缓存的最大时间。
    * Pragma: no-cache。其他用户http1.1，这个用于http1.0
* 安全方面考量：
    * X-Content-Type-Options，要求浏览器强制信任响应头中的Content-Type，不能自行猜测和解析内容
    * Strict-Transport-Security，表示只能用https访问资源
    * X-XSS-Protection，由浏览器检查跨脚本攻击。虽然当前有CSP的保护，但是仍然可以为一些老旧的浏览器提供功能。
    * Content-Security-Policy，CSP，具体描述资源能否被http/https访问，eval是否能执行，等等一系列的内容安全策略。
    * X-Frame-Options 标识资源不能被iframe内嵌。
* SSL原理
* DNS原理
* CDN原理
* 跨域问题

## Linux-CPU
* 进程的状态
    * R，运行中或者处于可运行状态
    * D，即不可中断的阻塞状态，例如IO等待（会被硬件中断）
    * S，可中断的阻塞，例如sleep。
    * T，由信号触发的暂停态。
    * t，debugger触发的暂停态。
    * Z，僵尸态。
    * X，死亡状态，并不会显示。
    * W，内存映射时的状态，2.6后不存在。
* 进程间通信的机制
    * 信号
    * 信号量
    * 管道
        * 匿名，用于父子进程间
        * 有名，用于任意进程间
    * 消息队列
    * 共享内存
    * socket

## Linux-Memory
* 进程映射
    * 内核空间（高地址）
    * 用户空间（低地址）
        * 进程环境变量
        * 进程传入的参数
        * 进程的stack（向下增长）
        * 进程的mmap空间
        * 进程的heap（向上增长）
        * .bss 未初始化全局变量
        * .data 已初始化全局变量
        * .text 代码段
        * foribidden
* mmap
    * mmap是映射一个文件到内存到虚拟地址空间的mmap区域, 这会让mmap区域分配内存. 但其实在Linux2.6内核版本以后, mmap可以不指定文件进行内存的分配。
    * `void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);`
* brk
    brk是一种直接在heap上分配空间的技术，最简单的方式是brk的指针直接向上增长。老版本的方式会导致内存泄漏。
* 如何关闭swap
* 如何关闭oom
* 内存不足时linux的动作
    * swap
    * 释放`buffer/cache`
    * OOM
* `buffer/cache`
    * Linux内核2.6前:
        * buff, 文件写缓存, 主要是为了提升IO密集时的性能，内核先将数据写到缓冲，再同步到慢速设备磁盘上，进行削峰填谷。
        * cache, 文件读缓存，将文件读到缓存，其他进程如果读取相同文件，可以复用缓存。
    * Linux内核2.6后:
        * buffer, 是cache中文件相关的metadata, 维护了cache和硬盘文件的映射关系。
        * cache, 和文件相关的，就放在cache中。包含了老版本的buff和cache的功能。
    * buffer/cache的空间不是可以被全部回收的，因为buffer/cache的空间包含了除了文件io相关的缓存外，还有tmpfs、共享内存等无法被释放的内容
        * 因此当buffer/cache占用很大，又无法释放时，可以观察共享内存、tmpfs的占用情况。
        * df就能查tmpfs的部分。有时候往往是系统日志会占用大量的tmpfs，这时候要考虑限制系统日志。
        * `ipcs -m` 可以查共享内存部分。（ipcs可以查看共享内存、消息队列、信号量等进程间通信的数据）
    * 可以通过命令强制性释放，禁止在现网操作，因为这可能影响所有现网进程的io操作。
    ```
    echo 3 > /proc/sys/vm/drop_caches, 释放buff/cache
    echo 2 > /proc/sys/vm/drop_caches, 释放buff
    echo 1 > /proc/sys/vm/drop_caches, 释放cache
    ```
* 缓存击穿
    * 需要查的数据不存在于db中，也不存在与缓存，导致人为构造大量的请求打到该数据上，频繁的查询db，拖垮db。
    * 缓存空结果。这可能导致大量的请求不存在数据，浪费大量内存。考虑使用布隆过滤器。
* 缓存雪崩
    * 缓存过期的瞬间，在重新从db设置到缓存前，请求全部达到db上，拖垮db。
    * 缓存永远有效，通过一个异步操作定时更新缓存，或者请求的时候判断是否应该更新，如果需要，就对更新操作上锁。

## Linux-Network
* 三次握手的目的
    * 同步两端的传输序列号和两端接受缓冲区大小。
* 四次挥手的目的
    * 确保两端不会再有数据传输
    * 确保两端的数据都在网络中消逝
    * 避免影响新建立的链接
* timewait是2MSL的原因
    * 若果最后的ACK丢失，需要等待对端新的FIN，这两者加起来最长时间为2MSL，当超过2MSL都没收到新的FIN，基本可以确定对端已经收到了ACK。
* 重传机制原理
* 窗口机制原理
* syn queue 和 accept queue 原理
    * server收到syn包，将会建立socket，并放在syn queue中。
    * server收到ack，将会把socket从syn queue中取出，放到accept queue中。
    * 应用程序通过listen_socket.accept() 取出 accept queue 中的 socket。
* syn queue满时的处理
    * syncookies=0,tcp_abort_on_overflow=0, 直接忽略掉多余的syn，等待重试。
    * syncookies=0,tcp_abort_on_overflow=1, 多余syn返回rst。
    * syncookies=1, 根据请求的syn计算出一个客户端信息的cookies，再将cookies作为syn返回给客户端。客户端响应ack的时候，反算出cookeis和客户端信息，然后直接把socket建立放到accept队列中。完全再syn queue中缓存。
* accept queue满时的处理
    * tcp_abort_on_overflow=0, 直接忽略ack，并重发syn+ack，等待客户端重新发ack。如果反复如此，则返回rst。
    * tcp_abort_on_overflow=1, 直接返回rst。
* 相关名词：
    * MSL，最长报文段寿命时间。由ttl确定。
    * MTU，最大传输单元，指的是IP数据报能经过一个物理网络的最大报文长度，一般是1500字节。包括了IP首部。
    * MSS，TCP最大报文段大小，不包括TCP首部长度和IP首部，如果数据包超过了MSS，就会进行分包。MSS = MTU - IP首部大小 - TCP首部大小
    * RTT，数据包往返时间。

## Redis
* redis模型
    * 单进程单线程，完全没有锁，单个命令的阻塞会导致整体的阻塞。
* redis持久化手段
    * RDB，周期生成快照的方案。
    * AOF，记录写操作命令，并周期进行整合。
* redis事务
    * 是一种乐观锁机制
* redis内存不足时的淘汰策略（redis配置的时候设定了redis可以占用的内存上限）
    * volatile-lru, 从具有ttl的数据集里面，选择最久未使用的数据进行淘汰。
    * volatile-ttl
    * volatile-random
    * allkeys-lru
    * allkeys-random
    * no-enviction
* redis集群宕机时候的数据迁移问题
* 性能优化
    * master不做持久化工作，持久化工作在slave上进行。
    * 避免设置大量的key在同一时间过期，因为过期操作会阻塞redis。尽量做一个随机数。

## MySQL
* 事务的四大特性
* 隔离级别
* 索引类型
* 会导致索引失效的情况
* explain mysql 性能查询

## Nginx & Openresty
* 什么是惊群，以及如何解决
    * 老版本nginx 开启 accept_mutex。
    * 新版本nginx可以使用reuseport。
    * 即便是老版本，惊群影响也不大，因为worker进程本身就很少，而且通常都是建立长链接。在并发量很大的时候，应该忽略惊群问题。
* Nginx的各个阶段
* openresty的各个阶段
* Nginx限流
    * 采用漏桶算法
    * `limit_req_zone key zone=name:size rate=rate [sync]`，key是指的对这个变量的出现速率进行限制；zone标识存储区域以及存储区域大小（其实就是漏桶的大小），超出漏洞的部分将会被拒绝；rate指的是具体速率。
    * `limit_req zone=name [burst=number]` 关联到漏桶，受到漏桶流出速率的限制。burst用于处理突发流量。
* 如何优化nginx网络性能
    * `sendfile on`， 直接在内核空间完成文件发送，这是一个linux的系统调用。
    * `tcp_nopush on`，默认就是开启的。开启后要响应收集满一个包后才进行响应。
    * `sendfile_max_chunk 1m;` 如果文件太大，就需要通过chunk进行分片传输。如果为0 就不做分片。默认为0。
    * `tcp_nodelay on`，关闭nagle算法，nagle算法会凑齐了mss包后才进行发包，关闭后只要有包就直接发送。
    * `accept_mutex off` ，目前默认为off。如果打开，则每次只有一个worker拿到一个新连接，如果关闭会通知所有进程新连接。其实关闭后是允许惊群的，但是互联网中经常都是高并发的长链接，打开后性能通常会更好些。
    * `multi_accept on`，目前默认是off。如果关闭，一个worker一次accept一个，否则accept所有queue中的socket。高并发的情况下，如果不能及时accept，会导致socket挤压，甚至被拒绝连接。高并发条件下需要及时清空accept queue。

## OAuth2.0
* OAuth2.0 的类型：
    * 授权码模式，先发起授权请求，再发起token请求。response_type为code，grant_type为authorization_code。
    * 隐含模式，先发起授权请求，重定向的时候直接会把token返回。response_type为token。
    * Resource Owner Password Credentials Grant，直接用用户的账号密码发起token请求，grant_type为password。
    * Client Credentials Grant，直接用分配给第三方的client_id 和 client_secret 发起token请求，grant_type为client_credential。
* state的作用
    * 防csrf攻击
* PKCE的原理和作用
* 认证和授权的关系

## OIDC
* OIDC 和 OAuth2.0 的关系
* OIDC 如何暴露信息，以及暴露了哪些信息
    * 通过 OIDC Discovery 协议暴露 OIDC 信息。将 OIDC Discovery 的 URL 交给第三方使用，返回的信息包括：
        * 认证授权URL
        * token的公钥jku
        * token的签名方式
        * authorize 支持的 response_type
        * token 支持的 grant_type
* jku 的作用
    * 由 OIDC Discovery 返回 jku
    * jku 里面是jwk的数组集合
    * jws 中，headers 里面的 kid 参数指出用 jku 中的哪个 jwk 进行验证。

## C++
* 什么是虚函数
* 什么是纯虚函数
* 什么是虚析构函数，有什么作用
* 虚函数的实现原理
    * 所有的C++对象都有一个隐藏对象，这个对象叫做vtbl，是一个数组，记录了所有的类中虚函数的地址。
    * 父类和子类中记录的vtbl是不同的，子类的vtbl记录的是自己重写后的虚函数地址。
    * 在进行调用的时候，是在vtbl中查该使用哪个函数地址。
* 什么是动态联编和静态联编
* 为什么动态联编不设置为默认的
    * 主要是效率问题，使用虚函数会带来额外的存储开销和调用开销。
    * C++的设计原则：任何会造成性能影响的特性只有在明确要求时才使用。
* C++ 类自带的函数
    ```
    MyClass(void);  // 默认带参构造函数 // 默认构造函数指不带参数或者所有参数都有缺省值的构造函数
    ~MyClass(void);  // 默认析构函数
    MyClass(const MyClass &);  // 默认拷贝构造函数
    MyClass & operator =(const MyClass &);  // 默认重载赋值运算符函数
    MyClass * operator &();  // 默认重载取址运算符函数
    MyClass const * operator &() const;  // 默认重载取址运算符const函数
    MyClass(MyClass &&);  // 默认移动构造函数
    MyClass & operator =(MyClass &&);  // 默认重载移动赋值操作符函数
    ```
* C++ 的成员变量初始化顺序
    * 和初始化列表的顺序无关，只和声明的顺序有关。

## 容器化技术
* 隔离技术
* 资源限制技术
* 文件系统

## 分布式相关
* 一致性hash的目的：
    * 节点进行数据存储时，往往会通过key的hash值 % 节点个数 N 来确定存储数据在哪个节点。这样的缺点在于如果有新机器加入以及有机器下线，会造成大量的缓存失效。
    * 在redis等分布式应用中经常使用一致性hash。
    * nginx可以通过一致性hash进行路由。
* 一致性hash原理
    * 将N个节点id做hash，这样会得到N个hash值，由于整数本质是个环，N个hash值其实就是分布在环的上的各个位置。数据读写时，判断key的hash值，将比key-hash大的且最接近的node取出（环上顺时针最近的一个node），把数据读写落在该节点上。
    * 当有新节点加入时，假设在AB节点中加入了E节点，只会影响A-E部分的缓存重建，不会让其他节点的缓存受到影响。
    * 如果直接用node-hash，其实存在数据倾斜问题，有可能某些节点获得的数据少，有些节点负责的数据少，这时候可以用虚拟节点：
        * 每个节点从节点id中进行扩展，例如node1可以扩展成node1-1 node1-2 node1-3，从1个node-hash，变成了3个node-hash。
        * 如此，一个节点存在M个node-hash，如果有N个节点，换上就有`N*M`个node-hash，因为hash值从概率上是比较均匀的，这样就构造了概率上均匀的`N*M`的分布。
        * `N*M`个node-hash，会和自己的原本的节点进行映射，当数据落在其中一个node-hash时，可以换算出原来的node是哪个。

## Celery
* 工作模型
    * 多进程监听MQ。MQ可以是rabbitmq / redis / db
## Python
## LUA
## 项目流程图
