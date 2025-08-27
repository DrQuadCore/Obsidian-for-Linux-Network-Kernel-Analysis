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
	// TSO 사용시 나눌 수 있는 최대 세그먼트 수 계산
	
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
		// 페이싱 체크

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
				// tso가 비활성화인 경우, nagle이 비활성화되어있지 않으면 종료
		} else {
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
		}

		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota,
						    nonagle);

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