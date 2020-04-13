
# 面试复习总结

<!-- TOC -->

- [面试复习总结](#面试复习总结)
    - [安全](#安全)
    - [http](#http)
    - [Linux-CPU](#linux-cpu)
    - [Linux-IO](#linux-io)
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
    * Pragma: no-cache。其他用于http1.1，这个用于http1.0
* 安全方面考量：
    * X-Content-Type-Options，要求浏览器强制信任响应头中的Content-Type，不能自行猜测和解析内容
    * Strict-Transport-Security，表示只能用https访问资源
    * X-XSS-Protection，由浏览器检查跨脚本攻击。虽然当前有CSP的保护，但是仍然可以为一些老旧的浏览器提供功能。
    * Content-Security-Policy，CSP，具体描述资源能否被http/https访问，eval是否能执行，等等一系列的内容安全策略。
    * X-Frame-Options 标识资源不能被iframe内嵌。
* SSL原理
    * 通过 SSL 证书来暴露自己的信息，服务器和客户端都可以有自己的证书。
        * SSL 证书信息包括 Subject、Issure、非对称加密公钥、Issure给证书的签名。
        * 证书签名可以用来保证证书的数据没有被篡改过，采用的校验共钥是 Issure 颁布的公钥。
        * Issure 的有效性通过相同的方式校验 Issure 的证书，直到某一个 Issure 是浏览器的受信证书。
    * 通过非对称加密实现加密密钥的交换。
        * 请求发起方使用对方证书暴露出的公钥，对加密密钥进行加密，然后请求接收方用证书私钥对其解密。
    * 通过对称加密对通信数据进行加密
        * 加密密钥由非对称加密进行确认。
* DNS原理
    * 本地hosts文件
    * 到本地记录的dns服务器进行请求
    * dns服务器有缓存就直接返回
    * dns服务器根服务器请求对应的域名解析服务器
    * 域名解析服务器返回对应的ip
* CDN原理
    * 本质上就是域名解析服务器根据请求者ip的地区返回不同的边缘节点ip。
* 跨域问题
    * jsonp
    * CORS

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
* 系统负载
    * 即 R 状态和 D 状态的进程数量
    * 每隔一段时间就进行一次统计
    * 进行1分钟平均、5分钟平、15分钟平均

## Linux-IO
* inode
    * 每个文件都有对应的一个inode，一个indoe中记录了很多元信息，包括：
        * 文件的字节数
        * 文件的读写权限
        * 文件的userid和groupid
        * 文件的时间戳：ctime, atime, mtime
        * inode的链接数
        * 文件内容对应的区块位置
    * 每个文件都有一个inode编号，指向对应的inode，inode编号记录在目录中。`ls -i ${filename}` 可以看对应文件的indoe编号。
    * 目录是一种特殊的文件，目录中的文件内容即：文件名以及对应的inode编号。所以目录也有对应的inode。
    * 硬连接：
        * inode中的链接数即硬连接。
        * inode的链接数为0时，才会清理磁盘。
        * 一个目录下的`.`和`..`分别是当前目录的硬连接，和上一级目录的硬连接。
    * 软链接，本质上是一个新的文件，会占用一个新的inode。文件内容是源文件的路径。
    * inode数据也会占用磁盘，被系统分配在一个特殊的盘上。如果磁盘未满，但是inode盘满了，是无法创建新文件的。

## Linux-Memory
* 进程映射
    * 内核空间（高地址）
        * 进程自有的信息，包括页表，进程信息等。这部分每个进程不一样。
        * 内核代码和数据。这部分每个进程共享。
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
* 内存不足时linux的动作
    * swap
    * 释放`buffer/cache`
    * OOM
    * swap 和 buff/cache 是较为安全的回收机制，操作系统需要判断当前内存不足时采用哪种。
        * `/proc/sys/vm/swappiness` 文件描述了内存不足时使用swap的优先级
        * swappiness 值越大，就越倾向于用 swap，否则倾向于用 buff/cache
        * swapiness 的值范围是 `0 - 200` ，即便为0并不是表示不会再swapiness，而是buff/cache清理也不够的情况下，还是会用swap的。
* 如何判断进程切换和中断带来的压力：
    * vmstat中的cs，表示上下文切换的次数
    * vmstat中的in，表示系统中断的次数
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
* 虚拟内存原理
    * linux的虚拟内存和windows的虚拟内存不是一个概念，windows的虚拟内存和linux的swap是一个概念。
    * 虚拟内存是对物理内存的抽象，从进程角度看到的是虚拟内存的分布。
    * 虚拟内存空间大小是 `2^N`，物理内存空间大小是 `2^M`，N和M 是可以不同的（也就是进程的角度可以看到的虚拟内存空间大小和实际物理内存大小不一样）。通常linux这两个值是相等的，常见的有32和64（即32bit的和64bit的地址空间）。
    * 虚拟内存会进行分页，物理内存也需要进行分页，这两者的分页大小是`必须一样`，否则无法有效的进行定位内存。
    * 每个进程启动都会有个虚拟内存地址空间，虚拟内存地址空间的数据是存放在`磁盘`中的，并没有在内存中，只有使用到某一部分时，才把该部分放到内存中。
    * 虚拟地址空间中的每个分页有三种状态：
        * 已缓存，表示该页已经复制到物理地址空间的页中了。
        * 已分配，表示该页存在数据，但是在磁盘中，没有在物理内存中缓存。
        * 未分配，表示该页不存在数据，也不会占用磁盘空间。
    * 虚拟地址空间中，每个页的状态，以及页对应的物理内存地址偏移等信息，都说记录在`页表`中的，页表中每一项（PTE）记录了一个页的状态和地址信息。
        * 每个进程的页表都是独立的，只维护本进程的虚拟地址空间的页和物理内存地址空间的页的关系。
        * 页表数据是属于虚拟地址空间的一部分，位于内核态中。
    * 在使用虚拟地址空间的时候，可能会发生三种状况：
        * 页命中。cpu寻址一个已缓存的页，直接从物理内存中获取数据即可。
        * 缺页。cpu寻址一个分配了数据，但是没有在物理内存中的页，只会触发异常，由操作系统将页放到物理内存中进行缓存，并在页表中修改页状态为`已缓存`。
            * 牺牲页。如果物理内存空间中的页已经满了，操作系统会选择一个页作为牺牲页换出到磁盘（如果数据有变更的话），并在页表中修改牺牲页的状态为`已分配`。
            * 牺牲页如果数据有变更，数据落盘应该就是记录在swapfile中的。
        * 段错误。通常是cpu使用一个未分配部分的虚拟地址空间中的页。

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
    * 超时重传
    * 快速重传
* 窗口机制原理
    * 流量窗口和用塞窗口共同决定发送的窗口大小。
    * 流量窗口
        * 接收方每次收到数据都告知发送方自己的可以进行数据接收的缓冲区大小，方便发送方了解接收方情况。
    * 拥塞控制
        * 慢启动，cwnd初始或是未达阈值，使用慢启动，cwnd指数增长。
            * 发生超时则阈值设置为cwnd/2，cwnd重置为1。（重新慢启动，达到阈值后用塞避免）
            * 接收到相同的ack，设置阈值为cwnd/2, cwnd重置为cwnd/2。（直接进入用塞避免，这其实就是快速恢复机制，快和慢塞相对的，一步到位进行用塞避免就是快，否则就是慢）
        * 拥塞控制，cwnd达到阈值后，进入拥塞避免模式，cwnd线性增长。
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
    * 主键索引
    * 普通索引
    * 唯一索引（也可以加快搜索速度的）
    * 全文索引
* 会导致索引失效的情况
    * where 用 or
    * where 用null
    * where 中字段用了计算
    * where 中用in
* explain mysql sql查询时候采用的索引等情况。具体的耗时情况还是需要用profile机制。
* show profiles，在profile功能打开时(set profiling=1;)，可以观察每个查询的耗时。（只能查查询语句）
* show profile for query ${queryid} 可以查看每个查询在每个环境的具体耗时情况。（只能查查询语句）
* show full processlist 可以观察每个连接的执行情况。
    * id，线程id。如果阻塞很长时间应该杀掉。
    * state，非常重要，是连接的状态。正常情况下应该多是sleep。
    * time，非常重要，是连接在state持续的时间。
    * info，非常重要，执行的sql语句。
* 字符集问题

## Nginx & Openresty
* 什么是惊群，以及如何解决
    * 老版本nginx 开启 accept_mutex。
    * 新版本nginx可以使用reuseport。
    * 即便是老版本，惊群影响也不大，因为worker进程本身就很少，而且通常都是建立长链接。在并发量很大的时候，应该忽略惊群问题。
* Nginx的各个阶段
* openresty的各个阶段
    * Init:
        * init_by_lua
        * init_worker_by_lua
    * Rewrite/Access
        * ssl_certificate_by_lua (if https)
        * set_by_lua
        * rewrite_by_lua: 转发、重定向、缓存等功能
        * access_by_lua IP: 准入、接口权限等情况集中处理
    * Content
        * content_by_lua: 内容生成
        * header_filter_by_lua: 响应头部过滤处理(例如添加头部信息)
        * content_filter_by_lua: 响应体过滤处理(例如转换响应内容)
    * Log
        * log_by_lua
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
    * 发送授权请求的时候传code_challenge（由code_verifier生成）
    * 发送token请求的时候，把code_verifier传给服务器，服务器把code_verifier和之前发送的code_challenge进行匹配。
    * pkce主要是用于native app，这时候的client_id/client_secret是容易被黑客拿到的，如果黑客拦截了code，就容易被黑客用来拿到token。
    * 用了pkce，黑客就算拿到了code和client_secret也没用，因为不知道code_verifier。
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
    * vtbl在编译时确定，属于类成员变量。
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
* delete 和 delete[] 的区别
    * `delete/delete[]` 都可以把 `new/new[]` 申请的内存区域全部释放掉
    * 如果是`new[]`申请的，delete只会调用首个元素的析构，`delete[]`会调用每个元素的析构。
    * 对于普通数据类型，调用`delete/delete[]`都ok，因为普通数据类型没有析构。
* 如果a是一个指针变量，a++意味这什么。
    * 如果 a 指向的数据类型是 type, 且一个type的数据类型有N字节，那么a++意味这指针向后移动N字节。

## 容器化技术
* 隔离技术， namespace，可以查到容器对哪些资源进行了隔离（即使用了namespace）`/proc/${container-pid}/ns`。
* 资源限制技术，cgroup
    * 当前系统
        * `/sys/fs/cgroup` 中描述了当前系统的资源限制情况，以及哪些资源可以做限制。
    * 子系统
        * 子系统其实就是在`/sys/fs/cgroup/${resource}`下的一个目录
        * 目录`/sys/fs/cgroup/${resource}/${sub-system}`创建的时候，会在其中自动生成资源限制文件，只需要改变其中的文件，就能对子系统做限制。
        * `/sys/fs/cgroup/${resource}/${sub-system}/tasks` 记录了一批 pid，描述了哪些进程受该子系统资源限制。
        * 对于docker而言，docker中的每个容器都受docker子系统的限制，容器中的每个进程又受容器子系统限制：
            * docker子系统: `/sys/fs/cgroup/${resource}/docker`，对所有的容器都进行限制。
            * 容器子系统: `/sys/fs/cgroup/${resource}/docker/${container_id}`，对容器中的所有进程都进行限制。
* 文件系统
    * 镜像分层

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
