---
Parameter:
  - sock
  - u32
Return: dst_entry
Location: /net/core/sock.c
---
```c
struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = __sk_dst_get(sk);

	if (dst && dst->obsolete &&
	    INDIRECT_CALL_INET(dst->ops->check, ip6_dst_check, ipv4_dst_check,
			       dst, cookie) == NULL) {
		sk_tx_queue_clear(sk); // sk과 NIC의 Tx queue 매핑 초기화 
		WRITE_ONCE(sk->sk_dst_pending_confirm, 0);
		RCU_INIT_POINTER(sk->sk_dst_cache, NULL); // NULL로 초기화
		dst_release(dst); // ref count 감소 
		return NULL;
	}

	return dst;
}
```

---
이전에 라우팅을 했을 때 그 결과인 struct dst_entry를 sk_dst_cache에 넣어두므로, struct sock에는 sk->sk_dst_cache 라는 라우트 캐시가 존재할 수 있다.

다음번에 같은 소켓으로 패킷을 보낼 경우, 이미 캐시된 dst를 재사용할 수 있는지 확인하는 함수가 __ sk_dst_get() 함수이다. 해당 함수에서 다시 호출하는 함수는 rcu_derefernce_check()으로, 캐시된 라우트 캐시를 읽을 때 socket lock이 잡혀 있거나 rcu read lock이 잡혀 있는지 확인한다. 

```c
static inline struct dst_entry *
__sk_dst_get(const struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache,
				     lockdep_sock_is_held(sk)); 
}
```

```c
/**
 * rcu_dereference_check() - rcu_dereference with debug checking 
 * @p: The pointer to read, prior to dereferencing 
 * @c: The conditions under which the dereference will take place 
 * 
 * Do an rcu_dereference(), but check that the conditions under which the 
 * dereference will take place are correct. Typically the conditions
 * indicate the various locking conditions that should be held at that
 * point.  The check should return true if the conditions are satisfied.
 * An implicit check for being in an RCU read-side critical section
 * (rcu_read_lock()) is included.
 */	
#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
				(c) || rcu_read_lock_held(), __rcu)
```

라우트 캐시가 존재하긴 하는데, obsolete 표시가 돼 있고, 프로토콜_dst_check() 함수를 통해 check를 해보았을 때 이 캐시된 라우트가 더 이상 유효하지 않다고 판단되면, 
(1) sk과 NIC의 Tx queue 매핑을 초기화하고, (2) sk_dst_pending_confirm을 초기화하고, (3) sk->sk_dst_cache를 NULL로 설정하고, (4) destination entry에 대한 reference count를 감소시킨다.

```c
	if (dst && dst->obsolete &&
	    INDIRECT_CALL_INET(dst->ops->check, ip6_dst_check, ipv4_dst_check,
			       dst, cookie) == NULL) {
		sk_tx_queue_clear(sk); // (1)
		WRITE_ONCE(sk->sk_dst_pending_confirm, 0); // (2)
		RCU_INIT_POINTER(sk->sk_dst_cache, NULL); // (3)
		dst_release(dst); // (4)
		return NULL;
	}
```


```c
static inline void sk_tx_queue_clear(struct sock *sk)
{
	/* Paired with READ_ONCE() in sk_tx_queue_get() and
	 * other WRITE_ONCE() because socket lock might be not held.
	 */
	WRITE_ONCE(sk->sk_tx_queue_mapping, NO_QUEUE_MAPPING);
}
```

- @sk_dst_pending_confirm: need to confirm neighbour

```c
INDIRECT_CALLABLE_SCOPE struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	struct rtable *rt = (struct rtable *) dst;

	/* All IPV4 dsts are created with ->obsolete set to the value
	 * DST_OBSOLETE_FORCE_CHK which forces validation calls down
	 * into this function always.
	 *
	 * When a PMTU/redirect information update invalidates a route,
	 * this is indicated by setting obsolete to DST_OBSOLETE_KILL or
	 * DST_OBSOLETE_DEAD.
	 */
	 // check() 함수로 다시 검증해 볼 대상이 아니거나, 이미 time out 되었다면
	if (dst->obsolete != DST_OBSOLETE_FORCE_CHK || rt_is_expired(rt))
		return NULL;
	return dst;
}
```