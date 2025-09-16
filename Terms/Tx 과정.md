# Tx 과정
## Userspace
### send() / sendto()
- Userspace에서 send() 또는 sendto()을 호출합니다.
```c title=__libc_send()
ssize_t
__libc_send (int fd, const void *buf, size_t len, int flags)
{
#ifdef __ASSUME_SEND_SYSCALL
  return SYSCALL_CANCEL (send, fd, buf, len, flags);
#elif defined __ASSUME_SENDTO_SYSCALL
  return SYSCALL_CANCEL (sendto, fd, buf, len, flags, NULL, 0);
#else
  return SOCKETCALL_CANCEL (send, fd, buf, len, flags);
#endif
}
weak_alias (__libc_send, send)
weak_alias (__libc_send, __send)
libc_hidden_def (__send)
```

``` c title=__libc_sendto()
ssize_t
__libc_sendto (int fd, const void *buf, size_t len, int flags,
               __CONST_SOCKADDR_ARG addr, socklen_t addrlen)
{
#ifdef __ASSUME_SENDTO_SYSCALL
  return SYSCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
                         addrlen);
#else
  return SOCKETCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
                            addrlen);
#endif
}
weak_alias (__libc_sendto, sendto)
weak_alias (__libc_sendto, __sendto)
```
- send()를 호출했다면, \_\_libc_send()가, sendto()를 호출했다면 \_\_libc_sendto()가 호출됩니다.
	- 보통 이미 연결되어있는 상태(TCP 등)이면 send(), 그렇지 않다면(UDP 등) sendto()를 호출합니다.  
- weak_alias(A, B)를 통해 교체되어 실행되는 것입니다.
	- weak_alias(A, B)는 A에 대한 alias B를 만듭니다.
- SYSCALL_CANCEL() 매크로를 통해 system call의 구현체들이 호출됩니다.
- send()와 sendto()에 대한 구현은 환경에 따라 다를 수 있습니다.
	- 현재 코드는 x86_64에 ubuntu 24.04 환경의 코드입니다.
	- glibc/sysdeps/unix/sysv/linux/에 구현되어있습니다.

### SYSCALL_DEFINE()
- SYSCALL_CANCLE 매크로 호출 시, 내부적으로 system call table을 참조하여 알맞는 매크로 함수가 실행됩니다.
```c
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
                unsigned int, flags)
{
        return __sys_sendto(fd, buff, len, flags, NULL, 0);
}
```
- send() 호출 시 최종적으로 호출되는 매크로 함수입니다.
- 이미 연결되어있는 상태이므로 addr과 addr_len의 값을 넣어주지 않습니다.

```c
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
                unsigned int, flags, struct sockaddr __user *, addr,
                int, addr_len)
{
        return __sys_sendto(fd, buff, len, flags, addr, addr_len);
}
```
- sendto() 호출 시 최종적으로 호출되는 매크로 함수입니다.

## Kernel Space by Syscall
### struct
```c
#define sockaddr_storage __kernel_sockaddr_storage
```
- linux/include/linux/socket.h에 정의되어 있습니다.

```c
struct __kernel_sockaddr_storage {
        union {
                struct {
                        __kernel_sa_family_t    ss_family; /* address family */
                        /* Following field(s) are implementation specific */
                        char __data[_K_SS_MAXSIZE - sizeof(unsigned short)];
                                /* space to achieve desired size, */
                                /* _SS_MAXSIZE value minus size of ss_family */
                };
                void *__align; /* implementation specific desired alignment */
        };
};
```
- linux/include/uapi/linux/socket.h에 정의되어 있습니다.

```c
struct msghdr {
        void            *msg_name;      /* ptr to socket address structure */
        int             msg_namelen;    /* size of socket address structure */

        int             msg_inq;        /* output, data left in socket */

        struct iov_iter msg_iter;       /* data */

        /*
         * Ancillary data. msg_control_user is the user buffer used for the
         * recv* side when msg_control_is_user is set, msg_control is the kernel
         * buffer used for all other cases.
         */
        union {
                void            *msg_control;
                void __user     *msg_control_user;
        };
        bool            msg_control_is_user : 1;
        bool            msg_get_inq : 1;/* return INQ after receive */
        unsigned int    msg_flags;      /* flags on received message */
        __kernel_size_t msg_controllen; /* ancillary data buffer length */
        struct kiocb    *msg_iocb;      /* ptr to iocb for async requests */
        struct ubuf_info *msg_ubuf;
        int (*sg_from_iter)(struct sk_buff *skb,
                            struct iov_iter *from, size_t length);
};
```
- linux/include/linux/socket.h에 정의되어 있습니다.
### \_\_sys_sendto()
```c
int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
                 struct sockaddr __user *addr,  int addr_len)
{
        struct socket *sock;
        struct sockaddr_storage address;
        int err;
        struct msghdr msg;

        err = import_ubuf(ITER_SOURCE, buff, len, &msg.msg_iter);
        //msg_iter 멤버 초기화
        
        if (unlikely(err))
                return err;

        CLASS(fd, f)(fd);
        if (fd_empty(f))
                return -EBADF;
        sock = sock_from_file(fd_file(f));
        if (unlikely(!sock))
                return -ENOTSOCK;

        msg.msg_name = NULL;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_namelen = 0;
        msg.msg_ubuf = NULL;
        if (addr) {
                err = move_addr_to_kernel(addr, addr_len, &address);
                if (err < 0)
                        return err;
                msg.msg_name = (struct sockaddr *)&address;
                msg.msg_namelen = addr_len;
        }
        flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;
        if (sock->file->f_flags & O_NONBLOCK)
                flags |= MSG_DONTWAIT;
        msg.msg_flags = flags;
        return __sock_sendmsg(sock, &msg);
}         
```
- net/socket.c에 구현되어 있습니다.
- import_ubuf()를 통해 userspace buffer에 있는 데이터를 kernel space으로 복사할 준비를 합니다.
	- msg는 sendmsg 함수에 전달될 메세지 헤더 struct입니다.
- fd가 유효한지를 확인하고 fd로부터 sock을 가져옵니다.
- addr이 NULL이 아니라면 (즉, sendto()로부터 호출되었다면)
	- 주소 정보를 커널 내 구조체인 sockaddr_storage address에 복사합니다.
- sock, msg를 매개변수로 사용하여 \_\_sock_sendmsg()를 호출합니다.
### import_ubuf()
```c
int import_ubuf(int rw, void __user *buf, size_t len, struct iov_iter *i)
{
        if (len > MAX_RW_COUNT)
                len = MAX_RW_COUNT;
        if (unlikely(!access_ok(buf, len)))
                return -EFAULT;

        iov_iter_ubuf(i, rw, buf, len);
        return 0;
}
EXPORT_SYMBOL_GPL(import_ubuf);
```
- include/lib/iov_iter.c에 구현되어있습니다.
- 최대 길이와 접근 가능 여부를 확인하고 iov_iter_ubuf()를 통해 구조체를 초기화합니다.

```c
static inline void iov_iter_ubuf(struct iov_iter *i, unsigned int direction,
                        void __user *buf, size_t count)
{
        WARN_ON(direction & ~(READ | WRITE));
        *i = (struct iov_iter) {
                .iter_type = ITER_UBUF,
                .data_source = direction,
                .ubuf = buf,
                .count = count,
                .nr_segs = 1
        };
}
```
- include/linux/uio.h에 구현되어있습니다.
- 구조체를 초기화하여 데이터를 복사할 준비를 합니다.

### \_\_sock_sendmsg()
```c
static int __sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
        int err = security_socket_sendmsg(sock, msg,
                                          msg_data_left(msg));

        return err ?: sock_sendmsg_nosec(sock, msg);
}
```
- net/socket.c에 구현되어있습니다.
- 이 소켓을 통해 이 msg를 보내도 되는지 보안 검사를 진행하고 err가 발생하면 err code를, 아니라면 sock_sendmsg_nosec()을 호출합니다.
### sock_sendmsg_nosec()
```c
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
        int ret = INDIRECT_CALL_INET(READ_ONCE(sock->ops)->sendmsg, inet6_sendmsg,
                                     inet_sendmsg, sock, msg,
                                     msg_data_left(msg));
        BUG_ON(ret == -EIOCBQUEUED);

        if (trace_sock_send_length_enabled())
                call_trace_sock_send_length(sock->sk, ret, 0);
        return ret;
}
```
- net/socket.c에 구현되어있습니다.
- 매크로 함수를 통해 동적으로 IP의 version에 따라 sendmsg 함수를 호출합니다.
	- v4라면 inet_sendmsg를 호출하고 매개변수로 sock, msg, msg_data_left(msg)를 사용합니다.
- 이후, 전송한 byte 수를 반환합니다.
### inet_sendmsg()
```c
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
        struct sock *sk = sock->sk;

        if (unlikely(inet_send_prepare(sk)))
                return -EAGAIN;

        return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udp_sendmsg,
                               sk, msg, size);
}
```
- net/ipv4/af_inet.c에 구현되어있습니다.
- inet_send_prepare()를 통해 소켓이 전송 가능한 상태인지 검사합니다.
- 매크로 함수를 통해 프로토콜에 따른 sendmsg 함수를 호출합니다.
	- tcp는 tcp_sendmsg()를, udp는 udp_sendmsg()를 호출합니다.
### inet_send_prepare()
```c
int inet_send_prepare(struct sock *sk)
{
        sock_rps_record_flow(sk);

        /* We may need to bind the socket. */
        if (data_race(!inet_sk(sk)->inet_num) && !sk->sk_prot->no_autobind &&
            inet_autobind(sk))
                return -EAGAIN;

        return 0;
}
```
-  net/ipv4/af_inet.c에 구현되어있습니다.
- RPS flow를 기록합니다.
- sk에 port가 바인딩되어있지 않다면 자동으로 port를 바인딩합니다.
### tcp_sendmsg()
```c
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
        int ret;

        lock_sock(sk);
        ret = tcp_sendmsg_locked(sk, msg, size);
        release_sock(sk);

        return ret;
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
- sk에 대해 lock을 획득하고 tcp_sendmsg_locked() 함수를 호출합니다.
### tcp_sendmsg_locked()
```c
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net_devmem_dmabuf_binding *binding = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;
	struct sockcm_cookie sockc;
	int flags, err, copied = 0;
	int mss_now = 0, size_goal, copied_syn = 0;
	int process_backlog = 0;
	int sockc_err = 0;
	int zc = 0;
	long timeo;

	flags = msg->msg_flags;

	sockc = (struct sockcm_cookie){ .tsflags = READ_ONCE(sk->sk_tsflags) };
	if (msg->msg_controllen) {
		sockc_err = sock_cmsg_send(sk, msg, &sockc);
		/* Don't return error until MSG_FASTOPEN has been processed;
		 * that may succeed even if the cmsg is invalid.
		 */
	}

	if ((flags & MSG_ZEROCOPY) && size) {
		if (msg->msg_ubuf) {
			uarg = msg->msg_ubuf;
			if (sk->sk_route_caps & NETIF_F_SG)
				zc = MSG_ZEROCOPY;
		} else if (sock_flag(sk, SOCK_ZEROCOPY)) {
			skb = tcp_write_queue_tail(sk);
			uarg = msg_zerocopy_realloc(sk, size, skb_zcopy(skb),
						    !sockc_err && sockc.dmabuf_id);
			if (!uarg) {
				err = -ENOBUFS;
				goto out_err;
			}
			if (sk->sk_route_caps & NETIF_F_SG)
				zc = MSG_ZEROCOPY;
			else
				uarg_to_msgzc(uarg)->zerocopy = 0;

			if (!sockc_err && sockc.dmabuf_id) {
				binding = net_devmem_get_binding(sk, sockc.dmabuf_id);
				if (IS_ERR(binding)) {
					err = PTR_ERR(binding);
					binding = NULL;
					goto out_err;
				}
			}
		}
	} else if (unlikely(msg->msg_flags & MSG_SPLICE_PAGES) && size) {
		if (sk->sk_route_caps & NETIF_F_SG)
			zc = MSG_SPLICE_PAGES;
	}

	if (!sockc_err && sockc.dmabuf_id &&
	    (!(flags & MSG_ZEROCOPY) || !sock_flag(sk, SOCK_ZEROCOPY))) {
		err = -EINVAL;
		goto out_err;
	}

	if (unlikely(flags & MSG_FASTOPEN ||
		     inet_test_bit(DEFER_CONNECT, sk)) &&
	    !tp->repair) {
		err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size, uarg);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 전송 타임아웃 계산

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */
	// 제한속도 체크

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}
	// TCP 연결이 되었거나 종료 중이 아니라면, 연결을 대기한다

	if (unlikely(tp->repair)) { // tcp의 repair 모드가 설정되어있는지 확인
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			copied = tcp_send_rcvq(sk, msg, size);
			goto out_nopush;
		}
		// 수신 큐로 전송, 소켓 정보(경로 등)가 제대로 변경되었는지 테스트(시뮬레이션)하고자 수신 큐로 보내보는 것. 일반적인 TCP 전송에서는 발생하지 않는 경로.

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;
		// repair queue가 설정안되어 있으면 오류
		/* 'common' sending to sendq */
	}

	if (sockc_err) {
		err = sockc_err;
		goto out_err;
	}

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Ok commence sending. */
	copied = 0;

restart:
	mss_now = tcp_send_mss(sk, &size_goal, flags);
	// mss 계산 및 size_goal 변수 초기화
	
	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;
	// 에러가 발생했거나 종료되었는지 체크

	while (msg_data_left(msg)) { // 남아있는 msg에 대해 반복
		int copy = 0;

		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;
		// write queue로부터 skb 가져오고 skb가 null이 아니라면 copy값 감소
		
		trace_tcp_sendmsg_locked(sk, msg, skb, size_goal);

		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) { // 첫 번째 skb인 경우
			bool first_skb;
	
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_space;

			if (unlikely(process_backlog >= 16)) {
				process_backlog = 0;
				if (sk_flush_backlog(sk))
					goto restart;
			}
			//process_backlog가 꽉찼다면 flush합니다
			
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			// rtx와 write 큐가 비어있는지 확인
			skb = tcp_stream_alloc_skb(sk, sk->sk_allocation,
						   first_skb);
			// skb 할당
			if (!skb)
				goto wait_for_space;

			process_backlog++;

#ifdef CONFIG_SKB_DECRYPTED
			skb->decrypted = !!(flags & MSG_SENDPAGE_DECRYPTED);
#endif
			tcp_skb_entail(sk, skb);
			// write 큐에 enqueue
			copy = size_goal;
			// copy값을 size_goal 값으로 변경
			/* All packets are restored as if they have
			 * already been sent. skb_mstamp_ns isn't set to
			 * avoid wrong rtt estimation.
			 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);
		// copy값이 남은 msg보다 크다면 msg로 변경
		
		if (zc == 0) { // 일반적인 경로
			bool merge = true;
			int i = skb_shinfo(skb)->nr_frags;
			struct page_frag *pfrag = sk_page_frag(sk);

			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_space;
			// prfrag에 새 page를 할당
			
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) { // skb를 coalescing할 수 없는 경우
				if (i >= READ_ONCE(net_hotdata.sysctl_max_skb_frags)) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				} // frag이 최댓값 이상이라면 push라고 마킹
				merge = false;
			}

			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			// 페이지에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (unlikely(skb_zcopy_pure(skb) || skb_zcopy_managed(skb))) {
				if (tcp_downgrade_zcopy_pure(sk, skb))
					goto wait_for_space;
				skb_zcopy_downgrade_managed(skb);
			}

			copy = tcp_wmem_schedule(sk, copy);
			// wmem에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (!copy)
				goto wait_for_space;

			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			// 데이터를 skb로 복사합니다
			if (err)
				goto do_error;

			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}
			pfrag->offset += copy;
		} else if (zc == MSG_ZEROCOPY)  {
			/* First append to a fragless skb builds initial
			 * pure zerocopy skb
			 */
			if (!skb->len)
				skb_shinfo(skb)->flags |= SKBFL_PURE_ZEROCOPY;

			if (!skb_zcopy_pure(skb)) {
				copy = tcp_wmem_schedule(sk, copy);
				if (!copy)
					goto wait_for_space;
			}

			err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg,
						       binding);
			if (err == -EMSGSIZE || err == -EEXIST) {
				tcp_mark_push(tp, skb);
				goto new_segment;
			}
			if (err < 0)
				goto do_error;
			copy = err;
		} else if (zc == MSG_SPLICE_PAGES) {
			/* Splice in data if we can; copy if we can't. */
			if (tcp_downgrade_zcopy_pure(sk, skb))
				goto wait_for_space;
			copy = tcp_wmem_schedule(sk, copy);
			if (!copy)
				goto wait_for_space;

			err = skb_splice_from_iter(skb, &msg->msg_iter, copy,
						   sk->sk_allocation);
			if (err < 0) {
				if (err == -EMSGSIZE) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				}
				goto do_error;
			}
			copy = err;

			if (!(flags & MSG_NO_SHARED_FRAGS))
				skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;

			sk_wmem_queued_add(sk, copy);
			sk_mem_charge(sk, copy);
		}

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		WRITE_ONCE(tp->write_seq, tp->write_seq + copy);
		TCP_SKB_CB(skb)->end_seq += copy;
		tcp_skb_pcount_set(skb, 0);
		// tcp seq num 설정

		copied += copy;
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		} // 보낼 msg가 더이상 없다면 out label로 이동

		if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		// 즉시 전송을 해야한다면 대기 중인 모든 세그먼트들을 넘김
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
			// 현재 skb가 write 큐 맨 앞에 있으면 즉시 전송
		continue;

wait_for_space:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		tcp_remove_empty_skb(sk);
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now,
				 TCP_NAGLE_PUSH, size_goal);

		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied) {
		tcp_tx_timestamp(sk, &sockc);
		tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);
	} // 커널로 복사된 데이터가 있으면 다음 단계로 넘어감
out_nopush:
	/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */
	if (uarg && !msg->msg_ubuf)
		net_zcopy_put(uarg);
	if (binding)
		net_devmem_dmabuf_binding_put(binding);
	return copied + copied_syn;

do_error:
	tcp_remove_empty_skb(sk);

	if (copied + copied_syn)
		goto out;
out_err:
	/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */
	if (uarg && !msg->msg_ubuf)
		net_zcopy_put_abort(uarg, true);
	err = sk_stream_error(sk, flags, err);
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(tcp_rtx_and_write_queues_empty(sk) && err == -EAGAIN)) {
		sk->sk_write_space(sk);
		tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
	if (binding)
		net_devmem_dmabuf_binding_put(binding);

	return err;
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
	- linux 6.16과 6.15 버전에 따라 구현이 다릅니다.
		- 6.16은 25년 7월 27일에, 6.15는 25년 5월 25일에 배포되었습니다.
		- 6.16에 제로카피 관련 코드가 추가되었습니다.
- 17~23
	- 부가적인 control msg가 있는지 확인합니다.
	- 있다면, 해당 msg를 읽고 타임스탬프 기록, 패킷 우선순위 설정 등 msg따른 부가 처리를 진행합니다.
- 25~55
	- ZERO Copy 관련 코드입니다.
	- ZERO_COPY 플래그가 켜져있다면 msg_ubuf를 사용하고 있는지 확인합니다.
		- 즉, userspace의 버퍼에 대한 정보가 있는지를 확인합니다.
	- 있다면, uarg로 해당 정보를 옮깁니다.
	- msg_ubuf를 사용하고 있지 않으나, zero copy 플래그가 켜져있다면 uarg에 재할당을 시도합니다.
- 63~71
	- fast open 관련 로직입니다.
### sock_cmsg_send()
```c
int sock_cmsg_send(struct sock *sk, struct msghdr *msg,
		   struct sockcm_cookie *sockc)
{
	struct cmsghdr *cmsg;
	int ret;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;
		ret = __sock_cmsg_send(sk, cmsg, sockc);
		if (ret)
			return ret;
	}
	return 0;
}
```
- msg에 대해서 반복문을 돌리고 cmsg를 읽는다.
### \_\_sock_cmsg_cend()
```c
int __sock_cmsg_send(struct sock *sk, struct cmsghdr *cmsg,
		     struct sockcm_cookie *sockc)
{
	u32 tsflags;

	BUILD_BUG_ON(SOF_TIMESTAMPING_LAST == (1 << 31));

	switch (cmsg->cmsg_type) {
	case SO_MARK:
		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_RAW) &&
		    !ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;
		sockc->mark = *(u32 *)CMSG_DATA(cmsg);
		break;
	case SO_TIMESTAMPING_OLD:
	case SO_TIMESTAMPING_NEW:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;

		tsflags = *(u32 *)CMSG_DATA(cmsg);
		if (tsflags & ~SOF_TIMESTAMPING_TX_RECORD_MASK)
			return -EINVAL;

		sockc->tsflags &= ~SOF_TIMESTAMPING_TX_RECORD_MASK;
		sockc->tsflags |= tsflags;
		break;
	case SCM_TXTIME:
		if (!sock_flag(sk, SOCK_TXTIME))
			return -EINVAL;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u64)))
			return -EINVAL;
		sockc->transmit_time = get_unaligned((u64 *)CMSG_DATA(cmsg));
		break;
	case SCM_TS_OPT_ID:
		if (sk_is_tcp(sk))
			return -EINVAL;
		tsflags = READ_ONCE(sk->sk_tsflags);
		if (!(tsflags & SOF_TIMESTAMPING_OPT_ID))
			return -EINVAL;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;
		sockc->ts_opt_id = *(u32 *)CMSG_DATA(cmsg);
		sockc->tsflags |= SOCKCM_FLAG_TS_OPT_ID;
		break;
	/* SCM_RIGHTS and SCM_CREDENTIALS are semantically in SOL_UNIX. */
	case SCM_RIGHTS:
	case SCM_CREDENTIALS:
		break;
	case SO_PRIORITY:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;
		if (!sk_set_prio_allowed(sk, *(u32 *)CMSG_DATA(cmsg)))
			return -EPERM;
		sockc->priority = *(u32 *)CMSG_DATA(cmsg);
		break;
	case SCM_DEVMEM_DMABUF:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;
		sockc->dmabuf_id = *(u32 *)CMSG_DATA(cmsg);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
```
- cmsg_type에 따라 부가 처리를 진행한다.

### tcp_push()
```c
void tcp_push(struct sock *sk, int flags, int mss_now,
	      int nonagle, int size_goal)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	skb = tcp_write_queue_tail(sk);
	if (!skb)
		return;
	if (!(flags & MSG_MORE) || forced_push(tp))
		tcp_mark_push(tp, skb);

	tcp_mark_urg(tp, flags);

	if (tcp_should_autocork(sk, skb, size_goal)) {

		/* avoid atomic op if TSQ_THROTTLED bit is already set */
		if (!test_bit(TSQ_THROTTLED, &sk->sk_tsq_flags)) {
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTOCORKING);
			set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
			smp_mb__after_atomic();
		}
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED.
		 */
		if (refcount_read(&sk->sk_wmem_alloc) > skb->truesize)
			return;
	}

	if (flags & MSG_MORE)
		nonagle = TCP_NAGLE_CORK;

	__tcp_push_pending_frames(sk, mss_now, nonagle);
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
- write 큐에서 skb를 가져오고 MSG_MORE 플래그가 없거나 강제 push가 가능한 경우, 마킹을 진행합니다.
- MSB_OOB 플래그가 있다면, URG 플래그를 설정합니다.
- 자동 corking이 가능하다면 Transmit 큐에 대해서 플래그를 설정하여 지연시킵니다.
- MSG_MORE 플래그가 활성되어있는 경우, nonagle 값을 변경합니다.

### \_\_tcp_push_peding_frames()
```c
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_write_xmit(sk, cur_mss, nonagle, 0,
			   sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
- TCP 연결이 끊어졌다면 바로 종료합니다.
- 전송을 진행하고, 시간을 측정합니다.

### tcp_write_xmit()
```c
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	u32 cwnd_quota, max_segs;
	int result;
	bool is_cwnd_limited = false, is_rwnd_limited = false;

	sent_pkts = 0;

	tcp_mstamp_refresh(tp);
	if (!push_one) {
		/* Do MTU probing. */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	max_segs = tcp_tso_segs(sk, mss_now);
	// TSO 사용시 나눌 수 있는 최대 세그먼트 수 계산 (wnd 한도 고려 X)
	
	while ((skb = tcp_send_head(sk))) { // write 큐의 헤드에서 skb 추출
		unsigned int limit;
		int missing_bytes;

		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
			/* "skb_mstamp_ns" is used as a start point for the retransmit timer */
			tp->tcp_wstamp_ns = tp->tcp_clock_cache;
			skb_set_delivery_time(skb, tp->tcp_wstamp_ns, SKB_CLOCK_MONOTONIC);
			list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
			tcp_init_tso_segs(skb, mss_now);
			goto repair; /* Skip network transmission */
		}

		if (tcp_pacing_check(sk))
			break;

		cwnd_quota = tcp_cwnd_test(tp);
		if (!cwnd_quota) {
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				break;
		} // cwnd에서 더 보낼 수 있는 양 체크
		
		
		cwnd_quota = min(cwnd_quota, max_segs);
		missing_bytes = cwnd_quota * mss_now - skb->len;
		if (missing_bytes > 0)
			tcp_grow_skb(sk, skb, missing_bytes);
		// 보낼 수 있는 양보다 보내야 하는 양이 많다면 남은 데이터를 보내기 위해 skb 확장
		tso_segs = tcp_set_skb_tso_segs(skb, mss_now);
		// tso 활성화시, 몇 개의 segment가 나오는지 계산
		
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
			is_rwnd_limited = true;
			break;
		} // 윈도우가 충분한지 체크 ('s'wnd를 테스트하고 'r'wnd를 제한...?)

		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
				// tso segment가 1개인 경우, nagle 적용여부 확인
		} else {
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
				// cwnd나 rwnd에 의해 전송이 지연되어야하는지 확인
		}

		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota,
						    nonagle);
		// tso가 가능하다면 split 단위 계산

		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

		if (tcp_small_queue_check(sk, skb, 0))
			break;

		/* Argh, we hit an empty skb(), presumably a thread
		 * is sleeping in sendmsg()/sk_stream_wait_memory().
		 * We do not want to send a pure-ack packet and have
		 * a strange looking rtx queue with empty packet(s).
		 */
		if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)
			break;

		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;
		// skb 전송
repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		tcp_event_new_data_sent(sk, skb);

		tcp_minshall_update(tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);

		if (push_one)
			break;
	}

	if (is_rwnd_limited)
		tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);
	else
		tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);

	is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tcp_snd_cwnd(tp));
	if (likely(sent_pkts || is_cwnd_limited))
		tcp_cwnd_validate(sk, is_cwnd_limited);

	if (likely(sent_pkts)) {
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* Send one loss probe per tail loss episode. */
		if (push_one != 2)
			tcp_schedule_loss_probe(sk, false);
		return false;
	}
	return !tp->packets_out && !tcp_write_queue_empty(sk);
}
```


### tcp_transmit_skb
```c
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}
```
- tcp의 receive sequence number를 추가하여 함수를 호출합니다.
### \_\_tcp_transmit_skb()
```c
static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcp_key key;
	struct tcphdr *th;
	u64 prior_wstamp;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));
	// skb 유효성 검사
	tp = tcp_sk(sk);
	prior_wstamp = tp->tcp_wstamp_ns;
	tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);
	skb_set_delivery_time(skb, tp->tcp_wstamp_ns, SKB_CLOCK_MONOTONIC);
	// 타임스탬프 관련
	
	if (clone_it) { // clone_it이 1인 경우 skb 복제 (추후 재전송을 위해 복제)
		oskb = skb;

		tcp_skb_tsorted_save(oskb) {
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			// 이미 복사된 skb라면 (다른 곳에서 참조중이라면) deep copy
			else
				skb = skb_clone(oskb, gfp_mask);
				// 그렇지 않으면 shallow copy
		} tcp_skb_tsorted_restore(oskb);

		if (unlikely(!skb))
			return -ENOBUFS;
		/* retransmit skbs might have a non zero value in skb->dev
		 * because skb->dev is aliased with skb->rbnode.rb_left
		 */
		skb->dev = NULL;
	}

	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	tcp_get_current_key(sk, &key);
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
		// SYN 패킷인 경우
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &key); // SYN 패킷 용 옵션 추가
	} else {
		tcp_options_size = tcp_established_options(sk, skb, &opts, &key); // 그외 패킷용 옵션 추가
		/* Force a PSH flag on all (GSO) packets to expedite GRO flush
		 * at receiver : This slightly improve GRO performance.
		 * Note that we do not force the PSH flag for non GSO packets,
		 * because they might be sent under high congestion events,
		 * and in this case it is better to delay the delivery of 1-MSS
		 * packets and thus the corresponding ACK packet that would
		 * release the following packet.
		 */
		if (tcp_skb_pcount(skb) > 1)
			tcb->tcp_flags |= TCPHDR_PSH;
	} // TSO/GSO 패킷이면 PUSH 플래그 설정
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr); // tcp 헤더 사이즈

	/* We set skb->ooo_okay to one if this packet can select
	 * a different TX queue than prior packets of this flow,
	 * to avoid self inflicted reorders.
	 * The 'other' queue decision is based on current cpu number
	 * if XPS is enabled, or sk->sk_txhash otherwise.
	 * We can switch to another (and better) queue if:
	 * 1) No packet with payload is in qdisc/device queues.
	 *    Delays in TX completion can defeat the test
	 *    even if packets were already sent.
	 * 2) Or rtx queue is empty.
	 *    This mitigates above case if ACK packets for
	 *    all prior packets were already processed.
	 */
	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) ||
			tcp_rtx_queue_empty(sk);
	// write buffer와 retransmission queue가 비어있는 경우에만 xps 허용
	// order가 꼬이는 것을 방지지

	/* If we had to use memory reserve to allocate this skb,
	 * this might cause drops if packet is looped back :
	 * Other socket might not have SOCK_MEMALLOC.
	 * Packets not looped back do not care about pfmemalloc.
	 */
	skb->pfmemalloc = 0;

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);
	// skb에 헤더 포인터 수정
	skb_orphan(skb);
	// sk로부터 분리(참조 카운터 감소)
	skb->sk = sk;
	// accounting을 위해서 포인터만 남겨둠
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree; // skb desctructor 함수 할당
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);
	// 메모리 사용량 수정

	skb_set_dst_pending_confirm(skb, READ_ONCE(sk->sk_dst_pending_confirm));

	/* Build TCP header and checksum it. */
	th = (struct tcphdr *)skb->data;
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					(tcb->tcp_flags & TCPHDR_FLAGS_MASK));

	th->check		= 0;
	th->urg_ptr		= 0;
	// tcp 헤더 수정
	
	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	} //urg 모드 처리, 포인터 설정

	skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		th->window      = htons(tcp_select_window(sk));
		tcp_ecn_send(sk, skb, th, tcp_header_size);
		// SYN 패킷이 아닌 애들은 swnd보고 window 헤더 설정
	} else {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}

	tcp_options_write(th, tp, NULL, &opts, &key);

	if (tcp_key_is_md5(&key)) {
#ifdef CONFIG_TCP_MD5SIG
		/* Calculate the MD5 hash, as we have all we need now */
		sk_gso_disable(sk);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       key.md5_key, sk, skb);
#endif
	} else if (tcp_key_is_ao(&key)) {
		int err;

		err = tcp_ao_transmit_skb(sk, skb, key.ao_key, th,
					  opts.hash_location);
		if (err) {
			kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
			return -ENOMEM;
		}
	} // 그 외 옵션..

	/* BPF prog is the last one writing header option */
	bpf_skops_write_hdr_opt(sk, skb, NULL, NULL, 0, &opts);

	INDIRECT_CALL_INET(icsk->icsk_af_ops->send_check,
			   tcp_v6_send_check, tcp_v4_send_check,
			   sk, skb);
	// 체크섬 계산

	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		tcp_event_ack_sent(sk, rcv_nxt);

	if (skb->len != tcp_header_size) {
		tcp_event_data_sent(tp, sk);
		tp->data_segs_out += tcp_skb_pcount(skb);
		tp->bytes_sent += skb->len - tcp_header_size;
	}

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

	tp->segs_out += tcp_skb_pcount(skb);
	skb_set_hash_from_sk(skb, sk);
	/* OK, its time to fill skb_shinfo(skb)->gso_{segs|size} */
	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
	skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

	/* Leave earliest departure time in skb->tstamp (skb->skb_mstamp_ns) */

	/* Cleanup our debris for IP stacks */
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
			       sizeof(struct inet6_skb_parm)));

	tcp_add_tx_delay(skb, tp);

	err = INDIRECT_CALL_INET(icsk->icsk_af_ops->queue_xmit,
				 inet6_csk_xmit, ip_queue_xmit,
				 sk, skb, &inet->cork.fl);
	// l3로 이동

	if (unlikely(err > 0)) {
		tcp_enter_cwr(sk);
		err = net_xmit_eval(err);
	}
	if (!err && oskb) {
		tcp_update_skb_after_send(sk, oskb, prior_wstamp);
		tcp_rate_skb_sent(sk, oskb);
	}
	return err;
}
```

### ip_queue_xmit()
```c
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	return __ip_queue_xmit(sk, skb, fl, READ_ONCE(inet_sk(sk)->tos)); // ToS 정보 추가해서 다음 함수로로
}
```

### \_\_ip_queue_xmit()
```c
int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
		    __u8 tos)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	rt = skb_rtable(skb); // 라우팅 정보 가져옴
	if (rt) // 라우팅 정보 있는 경우
		goto packet_routed;

	/* Make sure we can route this packet. */
	rt = dst_rtable(__sk_dst_check(sk, 0));
	// 라우팅 정보가 유효한지 확인하고 라우팅 테이블을 가져옴
	if (!rt) { // 라우팅 테이블이 없으면
		inet_sk_init_flowi4(inet, fl4);
		// flow 정보가 담겨있는 fl4 변수 초기화

		/* sctp_v4_xmit() uses its own DSCP value */
		fl4->flowi4_tos = tos & INET_DSCP_MASK;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ip_route_output_flow(net, fl4, sk);
		// flow 기반으로 라우팅 테이블 조회
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);
	// skb에 dst 설정

packet_routed:
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	// ip 헤더 포인터 설정
	
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));
	if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);
	// 헤더 설정

	/* Transport layer set skb->h.foo itself. */

	if (inet_opt && inet_opt->opt.optlen) {
		iph->ihl += inet_opt->opt.optlen >> 2;
		ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt);
	}

	ip_select_ident_segs(net, skb, sk,
			     skb_shinfo(skb)->gso_segs ?: 1);

	/* TODO : should we use skb->sk here instead of sk ? */
	skb->priority = READ_ONCE(sk->sk_priority);
	skb->mark = READ_ONCE(sk->sk_mark);

	res = ip_local_out(net, sk, skb);
	// 다음 함수 호출
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	kfree_skb_reason(skb, SKB_DROP_REASON_IP_OUTNOROUTES);
	return -EHOSTUNREACH;
}
```

### ip_local_out()
```c
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(net, sk, skb);
	if (likely(err == 1))
		err = dst_output(net, sk, skb);

	return err;
}
```

### \_\_ip_local_out()
```c
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	IP_INC_STATS(net, IPSTATS_MIB_OUTREQUESTS);

	iph_set_totlen(iph, skb->len);
	// ip 헤더의 총 길이 설정
	ip_send_check(iph);
	// 체크섬 계산

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IP);

	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}
```


### dst_output()
```c
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	return INDIRECT_CALL_INET(READ_ONCE(skb_dst(skb)->output),
				  ip6_output, ip_output,
				  net, sk, skb);
}
```


### ip_output()
```c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev, *indev = skb->dev; // 

	skb->dev = dev;
	// skb->dev를 실제 패킷이 나가는 인터페이스로 설정
	skb->protocol = htons(ETH_P_IP);
	// 중복..?

	//netfilter postrouting 필터 적용
	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, indev, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```


### ip_finish_output()
```c
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int ret;

	ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
	switch (ret) {
	case NET_XMIT_SUCCESS:
		return __ip_finish_output(net, sk, skb);
	case NET_XMIT_CN:
		return __ip_finish_output(net, sk, skb) ? : ret;
	default:
		kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
		return ret;
	}
} //BPF(eBPF)가 있으면 관련 동작 처리
```


### \_\_ip_finish_output()
```c
static int __ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	unsigned int mtu;

#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm) { // NAT가 적용된 경우, 재라우팅..
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(net, sk, skb);
	}
#endif
	mtu = ip_skb_dst_mtu(sk, skb); //mtu 가져옴
	if (skb_is_gso(skb)) //gso/tso인 경우
		return ip_finish_output_gso(net, sk, skb, mtu);

	if (skb->len > mtu || IPCB(skb)->frag_max_size) 
	//mtu보다 skb가 더 커서 fragmentation이 필요한 경우
		return ip_fragment(net, sk, skb, mtu, ip_finish_output2);

	return ip_finish_output2(net, sk, skb);
}
```


### ip_finish_output2()
```c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = dst_rtable(dst);
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	bool is_v6gw = false;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

	/* OUTOCTETS should be counted after fragment */
	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		skb = skb_expand_head(skb, hh_len);
		// headrom이 헤더 공간보다 작으면 확장
		if (!skb)
			return -ENOMEM;
	}

	if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res != LWTUNNEL_XMIT_CONTINUE)
			return res;
	} // lwt 처리 (vxlan 등)

	rcu_read_lock();
	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	// next hop 정보 가져옴(v4면 arp, v6면 ndp)
	// v6인 경우, is_v6gw = true로 설정
	
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		// 유효성 검사
		/* if crossing protocols, can not use the cached header */
		res = neigh_output(neigh, skb, is_v6gw);
		rcu_read_unlock();
		return res;
	}
	rcu_read_unlock();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
	return PTR_ERR(neigh);
}
```


### neigh_output()
```c
static inline int neigh_output(struct neighbour *n, struct sk_buff *skb,
			       bool skip_cache)
{
	const struct hh_cache *hh = &n->hh;

	/* n->nud_state and hh->hh_len could be changed under us.
	 * neigh_hh_output() is taking care of the race later.
	 */
	if (!skip_cache &&
	    (READ_ONCE(n->nud_state) & NUD_CONNECTED) &&
	    READ_ONCE(hh->hh_len))
	    // skip_cache가 꺼져있고 next hop 정보가 유효한 경우,
	    // v6인 경우 skip
		return neigh_hh_output(hh, skb);

	return READ_ONCE(n->output)(n, skb);
}
```


### neigh_hh_output()
```c
static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int hh_alen = 0;
	unsigned int seq;
	unsigned int hh_len;

	do { //seqlock 동작
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = READ_ONCE(hh->hh_len);
		if (likely(hh_len <= HH_DATA_MOD)) {
		//헤더 길이가 유효하다면
			hh_alen = HH_DATA_MOD;
			//헤더 길이 수정

			/* skb_push() would proceed silently if we have room for
			 * the unaligned size but not for the aligned size:
			 * check headroom explicitly.
			 */
			if (likely(skb_headroom(skb) >= HH_DATA_MOD)) {
				/* this is inlined by gcc */
				memcpy(skb->data - HH_DATA_MOD, hh->hh_data,
				       HH_DATA_MOD);
				       
				// headrom의 크기가 충분하다면 데이터 복사
			}
		} else {
			hh_alen = HH_DATA_ALIGN(hh_len);
			//헤더 길이 조정
			if (likely(skb_headroom(skb) >= hh_alen)) {
				memcpy(skb->data - hh_alen, hh->hh_data,
				       hh_alen);
				// 데이터 복사
			}
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	if (WARN_ON_ONCE(skb_headroom(skb) < hh_alen)) {
		kfree_skb(skb);
		// headroom 크기가 충분하지 않으면 드랍
		return NET_XMIT_DROP;
	}

	__skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}
```


### dev_queue_xmit()
```c
static inline int dev_queue_xmit(struct sk_buff *skb)
{
	return __dev_queue_xmit(skb, NULL);
}
```


### \_\_dev_queue_xmit()
```c
/**
 * __dev_queue_xmit() - transmit a buffer
 * @skb:	buffer to transmit
 * @sb_dev:	suboordinate device used for L2 forwarding offload
 *
 * Queue a buffer for transmission to a network device. The caller must
 * have set the device and priority and built the buffer before calling
 * this function. The function can be called from an interrupt.
 *
 * When calling this method, interrupts MUST be enabled. This is because
 * the BH enable code must have IRQs enabled so that it will not deadlock.
 *
 * Regardless of the return value, the skb is consumed, so it is currently
 * difficult to retry a send to this method. (You can bump the ref count
 * before sending to hold a reference for retry if you are careful.)
 *
 * Return:
 * * 0				- buffer successfully transmitted
 * * positive qdisc return code	- NET_XMIT_DROP etc.
 * * negative errno		- other errors
 */
int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq = NULL;
	struct Qdisc *q;
	int rc = -ENOMEM;
	bool again = false;

	skb_reset_mac_header(skb);
	skb_assert_len(skb);
	//mac 헤더 초기화

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
		__skb_tstamp_tx(skb, NULL, NULL, skb->sk, SCM_TSTAMP_SCHED);

	/* Disable soft irqs for various locks below. Also
	 * stops preemption for RCU.
	 */
	rcu_read_lock_bh();
	// lock 획득 및 softirq 비활성화

	skb_update_prio(skb);

	qdisc_pkt_len_init(skb);
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_at_ingress = 0;
#endif
#ifdef CONFIG_NET_EGRESS
	if (static_branch_unlikely(&egress_needed_key)) {
		if (nf_hook_egress_active()) {
			skb = nf_hook_egress(skb, &rc, dev);
			if (!skb)
				goto out;
		} //netfilter egress hook 처리

		netdev_xmit_skip_txqueue(false);

		nf_skip_egress(skb, true);
		skb = sch_handle_egress(skb, &rc, dev);
		//qdisc 핸들러 호출
		if (!skb)
			goto out;
		nf_skip_egress(skb, false);

		if (netdev_xmit_txqueue_skipped())
			txq = netdev_tx_queue_mapping(dev, skb);
			// 패킷이 나갈 tx queue 결정
	}
#endif
	/* If device/qdisc don't need skb->dst, release it right now while
	 * its hot in this cpu cache.
	 */
	if (dev->priv_flags & IFF_XMIT_DST_RELEASE)
		skb_dst_drop(skb);
	else
		skb_dst_force(skb);

	if (!txq)
		txq = netdev_core_pick_tx(dev, skb, sb_dev);
			// tx queue가 설정되어 있지 않다면 xps로 나갈 큐 결정

	q = rcu_dereference_bh(txq->qdisc);
	
	trace_net_dev_queue(skb);
	if (q->enqueue) {
		rc = __dev_xmit_skb(skb, q, dev, txq);
		goto out;
	}

// 가상 장치인 경우, 처리리
	/* The device has no queue. Common case for software devices:
	 * loopback, all the sorts of tunnels...

	 * Really, it is unlikely that netif_tx_lock protection is necessary
	 * here.  (f.e. loopback and IP tunnels are clean ignoring statistics
	 * counters.)
	 * However, it is possible, that they rely on protection
	 * made by us here.

	 * Check this and shot the lock. It is not prone from deadlocks.
	 *Either shot noqueue qdisc, it is even simpler 8)
	 */
	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id(); /* ok because BHs are off */

		/* Other cpus might concurrently change txq->xmit_lock_owner
		 * to -1 or to their cpu id, but not to our id.
		 */
		if (READ_ONCE(txq->xmit_lock_owner) != cpu) {
			if (dev_xmit_recursion())
				goto recursion_alert;

			skb = validate_xmit_skb(skb, dev, &again);
			if (!skb)
				goto out;

			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_xmit_stopped(txq)) {
				dev_xmit_recursion_inc();
				skb = dev_hard_start_xmit(skb, dev, txq, &rc);
				dev_xmit_recursion_dec();
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			net_crit_ratelimited("Virtual device %s asks to queue packet!\n",
					     dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately
			 */
recursion_alert:
			net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
					     dev->name);
		}
	}

	rc = -ENETDOWN;
	rcu_read_unlock_bh();

	dev_core_stats_tx_dropped_inc(dev);
	kfree_skb_list(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}
```


### \_\_dev_xmit_skb()
```c
static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
				 struct net_device *dev,
				 struct netdev_queue *txq)
{
	spinlock_t *root_lock = qdisc_lock(q);
	struct sk_buff *to_free = NULL;
	bool contended;
	int rc;

	qdisc_calculate_pkt_len(skb, q);

	if (q->flags & TCQ_F_NOLOCK) {
	//qdisc 처리 시작
		if (q->flags & TCQ_F_CAN_BYPASS && nolock_qdisc_is_empty(q) &&
		    qdisc_run_begin(q)) {
		    // qdisc bypass가 켜져있고, qdisc가 비어있고 queue에 접근할 수 있다면,
			/* Retest nolock_qdisc_is_empty() within the protection
			 * of q->seqlock to protect from racing with requeuing.
			 */
			if (unlikely(!nolock_qdisc_is_empty(q))) {
				rc = dev_qdisc_enqueue(skb, q, &to_free, txq);
				__qdisc_run(q);
				qdisc_run_end(q);

				goto no_lock_out;
			} //queue가 비어있지 않다면 enqueue하고 qdisc 실행

			qdisc_bstats_cpu_update(q, skb);  
			if (sch_direct_xmit(skb, q, dev, txq, NULL, true) &&
			    !nolock_qdisc_is_empty(q))
				__qdisc_run(q);

			qdisc_run_end(q);
			return NET_XMIT_SUCCESS;
		}

		rc = dev_qdisc_enqueue(skb, q, &to_free, txq);
		qdisc_run(q);

no_lock_out:
		if (unlikely(to_free))
			kfree_skb_list_reason(to_free,
					      tcf_get_drop_reason(to_free));
		return rc;
	}

	if (unlikely(READ_ONCE(q->owner) == smp_processor_id())) {
		kfree_skb_reason(skb, SKB_DROP_REASON_TC_RECLASSIFY_LOOP);
		return NET_XMIT_DROP;
	}

	/*
	 * Heuristic to force contended enqueues to serialize on a
	 * separate lock before trying to get qdisc main lock.
	 * This permits qdisc->running owner to get the lock more
	 * often and dequeue packets faster.
	 * On PREEMPT_RT it is possible to preempt the qdisc owner during xmit
	 * and then other tasks will only enqueue packets. The packets will be
	 * sent after the qdisc owner is scheduled again. To prevent this
	 * scenario the task always serialize on the lock.
	 */
	contended = qdisc_is_running(q) || IS_ENABLED(CONFIG_PREEMPT_RT);
	if (unlikely(contended))
		spin_lock(&q->busylock);

	spin_lock(root_lock);
	if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED, &q->state))) {
		__qdisc_drop(skb, &to_free);
		rc = NET_XMIT_DROP;
	} else if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&
		   qdisc_run_begin(q)) {
		/*
		 * This is a work-conserving queue; there are no old skbs
		 * waiting to be sent out; and the qdisc is not running -
		 * xmit the skb directly.
		 */

		qdisc_bstats_update(q, skb);

		if (sch_direct_xmit(skb, q, dev, txq, root_lock, true)) {
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);
		}

		qdisc_run_end(q);
		rc = NET_XMIT_SUCCESS;
	} else {
		rc = dev_qdisc_enqueue(skb, q, &to_free, txq);
		if (qdisc_run_begin(q)) {
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);
			qdisc_run_end(q);
		}
	}
	spin_unlock(root_lock);
	if (unlikely(to_free))
		kfree_skb_list_reason(to_free, SKB_DROP_REASON_QDISC_DROP);
	if (unlikely(contended))
		spin_unlock(&q->busylock);
	return rc;
}
```


### \_\_qdisc_run()
```c
void __qdisc_run(struct Qdisc *q)
{
	int quota = READ_ONCE(net_hotdata.dev_tx_weight); //쿼터 지정
	int packets;

	while (qdisc_restart(q, &packets)) {
		quota -= packets;
		if (quota <= 0) { // 쿼터 소진시 softirq 스케쥴링
			if (q->flags & TCQ_F_NOLOCK)
				set_bit(__QDISC_STATE_MISSED, &q->state);
			else
				__netif_schedule(q);

			break;
		}
	}
}
```


### qdisc_restart()
```c
/*
 * NOTE: Called under qdisc_lock(q) with locally disabled BH.
 *
 * running seqcount guarantees only one CPU can process
 * this qdisc at a time. qdisc_lock(q) serializes queue accesses for
 * this queue.
 *
 *  netif_tx_lock serializes accesses to device driver.
 *
 *  qdisc_lock(q) and netif_tx_lock are mutually exclusive,
 *  if one is grabbed, another must be free.
 *
 * Note, that this procedure can be called by a watchdog timer
 *
 * Returns to the caller:
 *				0  - queue is empty or throttled.
 *				>0 - queue is not empty.
 *
 */
static inline bool qdisc_restart(struct Qdisc *q, int *packets)
{
	spinlock_t *root_lock = NULL;
	struct netdev_queue *txq;
	struct net_device *dev;
	struct sk_buff *skb;
	bool validate;

	/* Dequeue packet */
	skb = dequeue_skb(q, &validate, packets); // 패킷 가져옴
	if (unlikely(!skb))
		return false;

	if (!(q->flags & TCQ_F_NOLOCK))
		root_lock = qdisc_lock(q);

	dev = qdisc_dev(q); // 패킷이 전송될 device
	txq = skb_get_tx_queue(dev, skb); // txq 가져옴

	return sch_direct_xmit(skb, q, dev, txq, root_lock, validate);
}
```


### sch_direct_xmit()
```c
/*
 * Transmit possibly several skbs, and handle the return status as
 * required. Owning qdisc running bit guarantees that only one CPU
 * can execute this function.
 *
 * Returns to the caller:
 *				false  - hardware queue frozen backoff
 *				true   - feel free to send more pkts
 */
bool sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
		     struct net_device *dev, struct netdev_queue *txq,
		     spinlock_t *root_lock, bool validate)
{
	int ret = NETDEV_TX_BUSY;
	bool again = false;

	/* And release qdisc */
	if (root_lock)
		spin_unlock(root_lock);

	/* Note that we validate skb (GSO, checksum, ...) outside of locks */
	if (validate)
		skb = validate_xmit_skb_list(skb, dev, &again);

#ifdef CONFIG_XFRM_OFFLOAD
	if (unlikely(again)) {
		if (root_lock)
			spin_lock(root_lock);

		dev_requeue_skb(skb, q);
		return false;
	}
#endif

	if (likely(skb)) { // skb가 유효한 경우,
		HARD_TX_LOCK(dev, txq, smp_processor_id()); // 락 획득
		if (!netif_xmit_frozen_or_stopped(txq)) // tx큐가 멈춰있는지 확인
			skb = dev_hard_start_xmit(skb, dev, txq, &ret);
		else
			qdisc_maybe_clear_missed(q, txq);

		HARD_TX_UNLOCK(dev, txq);
	} else {
		if (root_lock)
			spin_lock(root_lock);
		return true;
	}

	if (root_lock)
		spin_lock(root_lock);

	if (!dev_xmit_complete(ret)) {
		/* Driver returned NETDEV_TX_BUSY - requeue skb */
		if (unlikely(ret != NETDEV_TX_BUSY))
			net_warn_ratelimited("BUG %s code %d qlen %d\n",
					     dev->name, ret, q->q.qlen);

		dev_requeue_skb(skb, q);
		return false;
	}

	return true;
}
```


### dev_hard_start_xmit()
```c
struct sk_buff *dev_hard_start_xmit(struct sk_buff *first, struct net_device *dev,
				    struct netdev_queue *txq, int *ret)
{
	struct sk_buff *skb = first;
	int rc = NETDEV_TX_OK;

	while (skb) {
		struct sk_buff *next = skb->next;

		skb_mark_not_on_list(skb);
		rc = xmit_one(skb, dev, txq, next != NULL); // skb 전송
		if (unlikely(!dev_xmit_complete(rc))) { // 전송 실패
			skb->next = next;
			goto out;
		}

		skb = next; // 다음 skb로 설정
		if (netif_tx_queue_stopped(txq) && skb) {
			rc = NETDEV_TX_BUSY;
			break;
		}
	}

out:
	*ret = rc;
	return skb;
}
```


### xmit_one()
```c
static int xmit_one(struct sk_buff *skb, struct net_device *dev,
		    struct netdev_queue *txq, bool more)
{
	unsigned int len;
	int rc;

	if (dev_nit_active_rcu(dev)) // 모니터링 여부
		dev_queue_xmit_nit(skb, dev);

	len = skb->len;
	trace_net_dev_start_xmit(skb, dev);
	rc = netdev_start_xmit(skb, dev, txq, more); // 패킷 전송
	trace_net_dev_xmit(skb, rc, dev, len);

	return rc;
}
```


### netdev_start_xmit()
```c
static inline netdev_tx_t netdev_start_xmit(struct sk_buff *skb, struct net_device *dev,
					    struct netdev_queue *txq, bool more)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	netdev_tx_t rc;

	rc = __netdev_start_xmit(ops, skb, dev, more); // 디바이스로 전송
	if (rc == NETDEV_TX_OK)
		txq_trans_update(dev, txq);

	return rc;
}
```


### \_\_netdev_start_xmit()
```c
static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
					      struct sk_buff *skb, struct net_device *dev,
					      bool more)
{
	netdev_xmit_set_more(more);
	return ops->ndo_start_xmit(skb, dev); // 드라이버로 넘김
}
```


### ice_start_xmit()
```c
/**
 * ice_start_xmit - Selects the correct VSI and Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t ice_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_vsi *vsi = np->vsi;
	struct ice_tx_ring *tx_ring;

	tx_ring = vsi->tx_rings[skb->queue_mapping]; // skb와 매핑된 tx_ring

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, ICE_MIN_TX_LEN)) //패딩
		return NETDEV_TX_OK;

	return ice_xmit_frame_ring(skb, tx_ring);
}
```


### ice_xmit_frame_ring()
```c
/**
 * ice_xmit_frame_ring - Sends buffer on Tx ring
 * @skb: send buffer
 * @tx_ring: ring to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t
ice_xmit_frame_ring(struct sk_buff *skb, struct ice_tx_ring *tx_ring)
{
	struct ice_tx_offload_params offload = { 0 };
	struct ice_vsi *vsi = tx_ring->vsi;
	struct ice_tx_buf *first;
	struct ethhdr *eth;
	unsigned int count;
	int tso, csum;

	ice_trace(xmit_frame_ring, tx_ring, skb);

	if (unlikely(ipv6_hopopt_jumbo_remove(skb)))
		goto out_drop;

	count = ice_xmit_desc_count(skb);
	if (ice_chk_linearize(skb, count)) {
		if (__skb_linearize(skb))
			goto out_drop;
		count = ice_txd_use_count(skb->len);
		tx_ring->ring_stats->tx_stats.tx_linearize++;
	}

	/* need: 1 descriptor per page * PAGE_SIZE/ICE_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_head_len/ICE_MAX_DATA_PER_TXD,
	 *       + 4 desc gap to avoid the cache line where head is,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	if (ice_maybe_stop_tx(tx_ring, count + ICE_DESCS_PER_CACHE_LINE +
			      ICE_DESCS_FOR_CTX_DESC)) {
		tx_ring->ring_stats->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* prefetch for bql data which is infrequently used */
	netdev_txq_bql_enqueue_prefetchw(txring_txq(tx_ring));

	offload.tx_ring = tx_ring;

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buf[tx_ring->next_to_use];
	first->skb = skb;
	first->type = ICE_TX_BUF_SKB;
	first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	first->gso_segs = 1;
	first->tx_flags = 0;

	/* prepare the VLAN tagging flags for Tx */
	ice_tx_prepare_vlan_flags(tx_ring, first);
	if (first->tx_flags & ICE_TX_FLAGS_HW_OUTER_SINGLE_VLAN) {
		offload.cd_qw1 |= (u64)(ICE_TX_DESC_DTYPE_CTX |
					(ICE_TX_CTX_DESC_IL2TAG2 <<
					ICE_TXD_CTX_QW1_CMD_S));
		offload.cd_l2tag2 = first->vid;
	}

	/* set up TSO offload */
	tso = ice_tso(first, &offload);
	if (tso < 0)
		goto out_drop;

	/* always set up Tx checksum offload */
	csum = ice_tx_csum(first, &offload);
	if (csum < 0)
		goto out_drop;

	/* allow CONTROL frames egress from main VSI if FW LLDP disabled */
	eth = (struct ethhdr *)skb_mac_header(skb);

	if ((ice_is_switchdev_running(vsi->back) ||
	     ice_lag_is_switchdev_running(vsi->back)) &&
	    vsi->type != ICE_VSI_SF)
		ice_eswitch_set_target_vsi(skb, &offload);
	else if (unlikely((skb->priority == TC_PRIO_CONTROL ||
			   eth->h_proto == htons(ETH_P_LLDP)) &&
			   vsi->type == ICE_VSI_PF &&
			   vsi->port_info->qos_cfg.is_sw_lldp))
		offload.cd_qw1 |= (u64)(ICE_TX_DESC_DTYPE_CTX |
					ICE_TX_CTX_DESC_SWTCH_UPLINK <<
					ICE_TXD_CTX_QW1_CMD_S);

	ice_tstamp(tx_ring, skb, first, &offload);
	//헤더 설정
	
	if (offload.cd_qw1 & ICE_TX_DESC_DTYPE_CTX) {
		struct ice_tx_ctx_desc *cdesc;
		u16 i = tx_ring->next_to_use;

		/* grab the next descriptor */
		cdesc = ICE_TX_CTX_DESC(tx_ring, i);
		i++;
		tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

		/* setup context descriptor */
		cdesc->tunneling_params = cpu_to_le32(offload.cd_tunnel_params);
		cdesc->l2tag2 = cpu_to_le16(offload.cd_l2tag2);
		cdesc->gcs = cpu_to_le16(offload.cd_gcs_params);
		cdesc->qw1 = cpu_to_le64(offload.cd_qw1);
	}

	ice_tx_map(tx_ring, first, &offload);
	return NETDEV_TX_OK;

out_drop:
	ice_trace(xmit_frame_ring_drop, tx_ring, skb);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}
```


### ice_tx_map()
```c
/**
 * ice_tx_map - Build the Tx descriptor
 * @tx_ring: ring to send buffer on
 * @first: first buffer info buffer to use
 * @off: pointer to struct that holds offload parameters
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit descriptor.
 */
static void
ice_tx_map(struct ice_tx_ring *tx_ring, struct ice_tx_buf *first,
	   struct ice_tx_offload_params *off)
{
	u64 td_offset, td_tag, td_cmd;
	u16 i = tx_ring->next_to_use;
	unsigned int data_len, size;
	struct ice_tx_desc *tx_desc;
	struct ice_tx_buf *tx_buf;
	struct sk_buff *skb;
	skb_frag_t *frag;
	dma_addr_t dma;
	bool kick;

	td_tag = off->td_l2tag1;
	td_cmd = off->td_cmd;
	td_offset = off->td_offset;
	skb = first->skb;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = ICE_TX_DESC(tx_ring, i); // 사용 가능한 디스크립터

	if (first->tx_flags & ICE_TX_FLAGS_HW_VLAN) {
		td_cmd |= (u64)ICE_TX_DESC_CMD_IL2TAG1;
		td_tag = first->vid;
	}

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
	// dma 주소 매핑
	tx_buf = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
	//fragments 처리
		unsigned int max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;

		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (ICE_MAX_READ_REQ_SIZE - 1);
		tx_desc->buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		 // 하드웨어가 처리할 수 있는 것보다 크기가 더 큰 경우 분할
		while (unlikely(size > ICE_MAX_DATA_PER_TXD)) {
			tx_desc->cmd_type_offset_bsz =
				ice_build_ctob(td_cmd, td_offset, max_data,
					       td_tag);

			tx_desc++;
			i++;

			if (i == tx_ring->count) {
				tx_desc = ICE_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;
			tx_desc->buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->cmd_type_offset_bsz = ice_build_ctob(td_cmd, td_offset,
							      size, td_tag);

		tx_desc++;
		i++;

		if (i == tx_ring->count) {
			tx_desc = ICE_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);
		//fragment에 주소 매핑

		tx_buf = &tx_ring->tx_buf[i];
		tx_buf->type = ICE_TX_BUF_FRAG;
	}

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(first->skb);

	i++;
	if (i == tx_ring->count)
		i = 0;

	/* write last descriptor with RS and EOP bits */
	td_cmd |= (u64)ICE_TXD_LAST_DESC_CMD;
	tx_desc->cmd_type_offset_bsz =
			ice_build_ctob(td_cmd, td_offset, size, td_tag);

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.
	 *
	 * We also use this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	tx_ring->next_to_use = i;

	ice_maybe_stop_tx(tx_ring, DESC_NEEDED);
	// tx_ring이 가득 찼는지 확인하고 가득 찼다면 멈춤.

	/* notify HW of packet */
	kick = __netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount,
				      netdev_xmit_more()); // NIC에게 알림.
	if (kick)
		/* notify HW of packet */
		writel(i, tx_ring->tail);

	return;

dma_error:
	/* clear DMA mappings for failed tx_buf map */
	for (;;) {
		tx_buf = &tx_ring->tx_buf[i];
		ice_unmap_and_free_tx_buf(tx_ring, tx_buf);
		if (tx_buf == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
}
```


### \_\_netdev_tx_sent_queue()
```c
/* Variant of netdev_tx_sent_queue() for drivers that are aware
 * that they should not test BQL status themselves.
 * We do want to change __QUEUE_STATE_STACK_XOFF only for the last
 * skb of a batch.
 * Returns true if the doorbell must be used to kick the NIC.
 */
static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					  unsigned int bytes,
					  bool xmit_more)
{
	if (xmit_more) {
#ifdef CONFIG_BQL
		dql_queued(&dev_queue->dql, bytes);
#endif
		return netif_tx_queue_stopped(dev_queue); // kick 생략
	}
	netdev_tx_sent_queue(dev_queue, bytes); // kick
	return true;
}
```


### netdev_tx_sent_queue()
```c
/**
 *	netdev_tx_sent_queue - report the number of bytes queued to a given tx queue
 *	@dev_queue: network device queue
 *	@bytes: number of bytes queued to the device queue
 *
 *	Report the number of bytes queued for sending/completion to the network
 *	device hardware queue. @bytes should be a good approximation and should
 *	exactly match netdev_completed_queue() @bytes.
 *	This is typically called once per packet, from ndo_start_xmit().
 */
static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					unsigned int bytes)
{
#ifdef CONFIG_BQL
	dql_queued(&dev_queue->dql, bytes);

	if (likely(dql_avail(&dev_queue->dql) >= 0))
		return;

	/* Paired with READ_ONCE() from dev_watchdog() */
	WRITE_ONCE(dev_queue->trans_start, jiffies);

	/* This barrier is paired with smp_mb() from dev_watchdog() */
	smp_mb__before_atomic();

	set_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);

	/*
	 * The XOFF flag must be set before checking the dql_avail below,
	 * because in netdev_tx_completed_queue we update the dql_completed
	 * before checking the XOFF flag.
	 */
	smp_mb__after_atomic();

	/* check again in case another CPU has just made room avail */
	if (unlikely(dql_avail(&dev_queue->dql) >= 0))
		clear_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);
#endif
}
```



