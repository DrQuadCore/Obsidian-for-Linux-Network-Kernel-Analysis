
```c
//tcp_sendmsg_locked()함수의 일부 코드
		//...
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
			//...		
```

### iov_iter

include/linux/uio.h에 정의되어 있다. 
```c
struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source; // READ/WRITE
	size_t iov_offset; 
	/*
	 * Hack alert: overlay ubuf_iovec with iovec + count, so
	 * that the members resolve correctly regardless of the type
	 * of iterator used. This means that you can use:
	 *
	 * &iter->__ubuf_iovec or iter->__iov
	 *
	 * interchangably for the user_backed cases, hence simplifying
	 * some of the cases that need to deal with both.
	 */
	union {
		/*
		 * This really should be a const, but we cannot do that without
		 * also modifying any of the zero-filling iter init functions.
		 * Leave it non-const for now, but it should be treated as such.
		 */
		struct iovec __ubuf_iovec; //유저 공간의 단일 버퍼
		struct {
			union {
				/* use iter_iov() to get the current vec */
				const struct iovec *__iov; //유저 버퍼 벡터
				const struct kvec *kvec; //커널 버퍼 벡터
				const struct bio_vec *bvec; //페이지 단위 블록 I/O 버퍼 벡터
				const struct folio_queue *folioq;
				struct xarray *xarray; 
				void __user *ubuf; //유저 버퍼 포인터
			};
			size_t count; //남은 바이트 수
		};
	};
	union {
		unsigned long nr_segs; // 남은 세그먼트의 수
		u8 folioq_slot;
		loff_t xarray_start;
	};
};

```
- 버퍼가 여러 chunks로 나뉘어 있을 수 있는데 이를 안전하게 다루기 위해 단일 스트림처럼 보이도록 하는 구조체이다.
- 변수
	- type: 이터레이터의 타입
	- data_source: 0이면 커널이 해당 포인터 주소로 데이터를 써주는 방향, 1이면 해당 포인터 주소로부터 커널이 데이터를 읽어오는 방향
	- iov_offset: 현재 가리키고 있는 iovec 내에서 오프셋
	- count: 처리해야하는 총 바이트 수
	- nr_segs: 처리되지 않고 남아있는 세그먼트의 수

```c
// 유저 스페이스의 메모리 주소를 가리키는 세그먼트
struct iovec
{
	void __user *iov_base;	// 데이터 시작 주소
	__kernel_size_t iov_len; // 데이터 길이
};
```
- writev()/sendmsg()에서 사용되는 타입이다.
- 하나의 연속된 세그먼트를 나타낸다.

### skb_copy_to_page_nocache

nocache는 일부 디바이스(Intel NIC 등)에서 제공하는 기술로 캐시에 쓰지않고 바로 메모리로 적는 기술이다.
유저스페이스에서 커널로 데이터를 복사한 이후 페이로드를 거의 읽지 않기 때문에 캐시를 사용하지 않는것이 성능상 좋을 수 있다.

include/net/sock.h에 정의되어 있다.
```c
static inline int skb_copy_to_page_nocache(struct sock *sk, 
						struct iov_iter *from, struct sk_buff *skb, 
						struct page *page, int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);
	if (err)
		return err;

	skb_len_add(skb, copy); //skb 페이로드 길이 증가
	sk_wmem_queued_add(sk, copy);
	sk_mem_charge(sk, copy);
	return 0;
}
```
- page: 커널의 목적지 버퍼 주소


```c
static inline int skb_do_copy_data_nocache(struct sock *sk, struct sk_buff *skb,
					   struct iov_iter *from, char *to,
					   int copy, int offset)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		__wsum csum = 0;
		if (!csum_and_copy_from_iter_full(to, copy, &csum, from))
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, offset);
	} else if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY) {
		if (!copy_from_iter_full_nocache(to, copy, from))
			return -EFAULT;
	} else if (!copy_from_iter_full(to, copy, from))
		return -EFAULT;

	return 0;
}
```
1. 체크섬 오프로드가 없는경우 소프트웨어가 check sum을 계산해야 한다.
	- csum에 이번에 복사한 구간의 체크섬을 모으고, csum_block_add()로 SKB 누적 체크섬에 더함
2. 캐시를 사용하지 않고 커널 스페이스로 데이터 복사하는 경로.
3. 일반적인 데이터 복사 경로이다.

- to가 char\*인 이유는 주소 연산을 바이트 단위로 하기위해

```c
bool copy_from_iter_full(void *addr, size_t bytes, struct iov_iter *i)
{
	size_t copied = copy_from_iter(addr, bytes, i);
	if (likely(copied == bytes))
		return true;
	iov_iter_revert(i, copied);
	return false;
}
```
전부 복사됐을 때만 성공으로 보고, 아니면 iov_iter의 포인터 위치를 원상복구 하기위해 iov_iter_revert() 호출

```c
size_t copy_from_iter(void *addr, size_t bytes, struct iov_iter *i)
{
	if (check_copy_size(addr, bytes, false))
		return _copy_from_iter(addr, bytes, i);
	return 0;
}

check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	// addr의 사용 가능한 최대 크기를 반환
	int sz = __builtin_object_size(addr, 0);
	if (unlikely(sz >= 0 && sz < bytes)) {
		if (!__builtin_constant_p(bytes))
			copy_overflow(sz, bytes);
		else if (is_source)
			__bad_copy_from();
		else
			__bad_copy_to();
		return false;
	}
	if (WARN_ON_ONCE(bytes > INT_MAX))
		return false;
	check_object_size(addr, bytes, is_source);
	return true;
}
```
- 버퍼 오버플로우 확인하고 에러 핸들링

```c
size_t _copy_from_iter(void *addr, size_t bytes, struct iov_iter *i)
{
	if (WARN_ON_ONCE(!i->data_source))
		return 0;
		
	if (user_backed_iter(i))
		might_fault();
	return __copy_from_iter(addr, bytes, i);
}

static inline bool user_backed_iter(const struct iov_iter *i)
{
	return iter_is_ubuf(i) || iter_is_iovec(i);
}

static inline bool iter_is_ubuf(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_UBUF;
}

// !!(condition)을 bool으로 캐스팅

#define WARN_ON_ONCE(condition) ({				\
	int __ret_warn_on = !!(condition);			\
	if (unlikely(__ret_warn_on))				\
		__WARN_FLAGS(BUGFLAG_ONCE |			\
			     BUGFLAG_TAINT(TAINT_WARN));	\
	unlikely(__ret_warn_on);				\
})
```



```c
size_t __copy_from_iter(void *addr, size_t bytes, struct iov_iter *i)
{
	return iterate_and_advance(i, bytes, addr,
				   copy_from_user_iter, memcpy_from_iter);
}

```


```c
size_t iterate_and_advance(struct iov_iter *iter, size_t len, void *priv,
			   iov_ustep_f ustep, iov_step_f step)
{
	return iterate_and_advance2(iter, len, priv, NULL, ustep, step);
}

// 콜백 함수로 함수의 주소값을 넘겨준다.
typedef size_t (*iov_ustep_f)(void __user *iter_base, size_t progress, 
			size_t len, void *priv, void *priv2);

```

```c
bool csum_and_copy_from_iter_full(void *addr, size_t bytes,
				  __wsum *csum, struct iov_iter *i)
{
	size_t copied;

	if (WARN_ON_ONCE(!i->data_source))
		return false;
	copied = iterate_and_advance2(i, bytes, addr, csum,
				      copy_from_user_iter_csum,
				      memcpy_from_iter_csum);
	if (likely(copied == bytes))
		return true;
	iov_iter_revert(i, copied);
	return false;
}
```


```c
size_t iterate_and_advance2(struct iov_iter *iter, size_t len, void *priv,
			    void *priv2, iov_ustep_f ustep, iov_step_f step)
{
	if (unlikely(iter->count < len))
		len = iter->count;
	if (unlikely(!len))
		return 0;
	// iter타입에따라
	if (likely(iter_is_ubuf(iter)))
		return iterate_ubuf(iter, len, priv, priv2, ustep);
	if (likely(iter_is_iovec(iter)))
		return iterate_iovec(iter, len, priv, priv2, ustep);
	if (iov_iter_is_bvec(iter))
		return iterate_bvec(iter, len, priv, priv2, step);
	if (iov_iter_is_kvec(iter))
		return iterate_kvec(iter, len, priv, priv2, step);
	if (iov_iter_is_folioq(iter))
		return iterate_folioq(iter, len, priv, priv2, step);
	if (iov_iter_is_xarray(iter))
		return iterate_xarray(iter, len, priv, priv2, step);
	return iterate_discard(iter, len, priv, priv2, step);
}

```

```c
size_t iterate_ubuf(struct iov_iter *iter, size_t len, void *priv, void *priv2,
		    iov_ustep_f step)
{
	void __user *base = iter->ubuf;
	size_t progress = 0, remain;

	remain = step(base + iter->iov_offset, 0, len, priv, priv2);
	progress = len - remain;
	iter->iov_offset += progress;
	iter->count -= progress;
	return progress;
}
```


```c
size_t iterate_iovec(struct iov_iter *iter, size_t len, void *priv, void *priv2,
		     iov_ustep_f step)
{
	const struct iovec *p = iter->__iov;
	size_t progress = 0, skip = iter->iov_offset;

	do {
		size_t remain, consumed;
		// len과 세그먼트에서 남은 크기 중 작은값
		size_t part = min(len, p->iov_len - skip); 

		if (likely(part)) {
			// skip부터 part바이트 만큼 복사
			remain = step(p->iov_base + skip, progress, part, priv, priv2);
			consumed = part - remain;
			progress += consumed;
			skip += consumed;
			len -= consumed;
			// len을 다 사용하면 while탈출
			if (skip < p->iov_len)
				break;
		}
		p++;
		skip = 0;
	} while (len);
	
	iter->nr_segs -= p - iter->__iov;
	iter->__iov = p;
	iter->iov_offset = skip;
	iter->count -= progress;
	return progress;
}
```
- \*iter에서 최대 len바이트를 처리

```c
size_t copy_from_user_iter(void __user *iter_from, size_t progress,
			   size_t len, void *to, void *priv2)
{
	size_t res = len;
	
	// 디버깅용
	if (should_fail_usercopy())
		return len;
	if (access_ok(iter_from, len)) {
		to += progress;
		// 커널 버퍼 유효성 검사
		instrument_copy_from_user_before(to, iter_from, len);
		res = raw_copy_from_user(to, iter_from, len);
		instrument_copy_from_user_after(to, iter_from, len, res);
	}
	return res;
}
```
실제로 복사가 이루어짐


아키텍쳐마다 다름,  x86기준 
```c
raw_copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	return copy_user_generic(dst, (__force void *)src, size);
}
```

arch/x86/include/asm/uaccess_64.h
```c
static __always_inline __must_check unsigned long copy_user_generic(void *to, const void *from, unsigned long len)
{
	// 커널 코드에서 유저 공간 메모리에 접근하기 직전에 CPU의 AC flag를 설정해 사용자 메모리 접근을 허용하는 역할을 함
	stac();
	
	/*
	 * If CPU has FSRM feature, use 'rep movs'.
	 * Otherwise, use rep_movs_alternative.
	 */
	asm volatile(
		"1:\n\t"
		ALTERNATIVE("rep movsb",
			    "call rep_movs_alternative", ALT_NOT(X86_FEATURE_FSRM))
		"2:\n"
		_ASM_EXTABLE_UA(1b, 2b)
		:"+c" (len), "+D" (to), "+S" (from), ASM_CALL_CONSTRAINT
		: : "memory", "rax");
	clac();
	return len;
}

//arch/x86/include/asm/smap.h
static __always_inline void stac(void)
{
	/* Note: a barrier is implicit in alternative() */
	alternative("", "stac", X86_FEATURE_SMAP);
}

//arch/x86/include/asm/cpufeatures.h

#define X86_FEATURE_SMAP		( 9*32+20) /* "smap" Supervisor Mode Access Prevention */

```
from에서 to로 데이터 복사 후 복사한 길이 반환

```c
void iov_iter_revert(struct iov_iter *i, size_t unroll)
{
	if (!unroll)
		return;
	if (WARN_ON(unroll > MAX_RW_COUNT))
		return;
	i->count += unroll;
	if (unlikely(iov_iter_is_discard(i)))
		return;
	if (unroll <= i->iov_offset) {
		i->iov_offset -= unroll;
		return;
	}
	unroll -= i->iov_offset;
	if (iov_iter_is_xarray(i) || iter_is_ubuf(i)) {
		BUG(); /* We should never go beyond the start of the specified
			* range since we might then be straying into pages that
			* aren't pinned.
			*/
	} else if (iov_iter_is_bvec(i)) {
		//세그먼트를 역방향으로 한 칸씩 되돌아가며 nr_segs를 증가
		const struct bio_vec *bvec = i->bvec;
		while (1) {
			size_t n = (--bvec)->bv_len;
			i->nr_segs++;
			if (unroll <= n) {
				i->bvec = bvec;
				i->iov_offset = n - unroll;
				return;
			}
			unroll -= n;
		}
	} else if (iov_iter_is_folioq(i)) {
		i->iov_offset = 0;
		iov_iter_folioq_revert(i, unroll);
	} else { /* same logics for iovec and kvec */
		const struct iovec *iov = iter_iov(i);
		while (1) {
			size_t n = (--iov)->iov_len;
			i->nr_segs++;
			if (unroll <= n) {
				i->__iov = iov;
				i->iov_offset = n - unroll;
				return;
			}
			unroll -= n;
		}
	}
}
```

이미 앞으로 진행된 iov_iter 커서를 rollback하는 함수이다.
복사/전송 도중 일부만 진행되었거나 에러가 나서 앞서 advance된 길이를 취소해야 할 때 사용한다.