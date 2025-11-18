---
Parameter: 
- sock *
Return:
- void
Location:
- include/net/rps.h
---

```c title=sock_rps_record_flow()
static inline void sock_rps_record_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	if (static_branch_unlikely(&rfs_needed)) {
		/* Reading sk->sk_rxhash might incur an expensive cache line
		 * miss.
		 *
		 * TCP_ESTABLISHED does cover almost all states where RFS
		 * might be useful, and is cheaper [1] than testing :
		 *	IPv4: inet_sk(sk)->inet_daddr
		 * 	IPv6: ipv6_addr_any(&sk->sk_v6_daddr)
		 * OR	an additional socket flag
		 * [1] : sk_state and sk_prot are in the same cache line.
		 */
		if (sk->sk_state == TCP_ESTABLISHED) {
			/* This READ_ONCE() is paired with the WRITE_ONCE()
			 * from sock_rps_save_rxhash() and sock_rps_reset_rxhash().
			 */
			sock_rps_record_flow_hash(READ_ONCE(sk->sk_rxhash)); //[[sock_rps_record_flow()#sock_rps_record_flow_hash()|sock_rps_record_flow_hash()]]
		}
	}
#endif
}
```

- `rfs_needed` 변수로 RFS가 활성화되어 있는지 확인한다.
```c
extern struct static_key_false rfs_needed;
```

- 현재 소켓의 상태가 `TCP_ESTABLISHED`인지 확인하는 것으로 RFS가 필요한지 아닌지를 구분할 수 있다.

---
### sock_rps_record_flow_hash()
```c title=sock_rps_record_flow_hash()
/*
 * The rps_sock_flow_table contains mappings of flows to the last CPU
 * on which they were processed by the application (set in recvmsg).
 * Each entry is a 32bit value. Upper part is the high-order bits
 * of flow hash, lower part is CPU number.
 * rps_cpu_mask is used to partition the space, depending on number of
 * possible CPUs : rps_cpu_mask = roundup_pow_of_two(nr_cpu_ids) - 1
 * For example, if 64 CPUs are possible, rps_cpu_mask = 0x3f,
 * meaning we use 32-6=26 bits for the hash.
 */
struct rps_sock_flow_table {
	u32	mask;

	u32	ents[] ____cacheline_aligned_in_smp;
};

static inline void sock_rps_record_flow_hash(__u32 hash)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	if (!hash)
		return;
	rcu_read_lock();
	sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
	//[[net_hotdata]]
	if (sock_flow_table)
		rps_record_sock_flow(sock_flow_table, hash);
	rcu_read_unlock();
#endif
}
```
- RCU 락을 잡는다. 이는 전역 변수인 `net_hotdata`의 멤버를 참조해야 하기 때문이다.

### net_hotdata
```c title=net_hotdata
// include/net/hotdata.h

/* Read mostly data used in network fast paths. */
struct net_hotdata {
#if IS_ENABLED(CONFIG_INET)
	...
#ifdef CONFIG_RPS
	struct rps_sock_flow_table __rcu *rps_sock_flow_table;
	u32			rps_cpu_mask;
#endif
	...
};
...
extern struct net_hotdata net_hotdata;

#endif /* _NET_HOTDATA_H */
```
- 이제 `rps_recode_sock_flow()`함수로 `sk->rxhash`의 값을 `sock_flow_table`에 저장한다.

---
### rps_record_sock_flow()
```c title=rps_record_sock_flow()
static inline void rps_record_sock_flow(struct rps_sock_flow_table *table,
					u32 hash)
{
	unsigned int index = hash & table->mask;
	u32 val = hash & ~net_hotdata.rps_cpu_mask;

	/* We only give a hint, preemption can change CPU under us */
	val |= raw_smp_processor_id();

	/* The following WRITE_ONCE() is paired with the READ_ONCE()
	 * here, and another one in get_rps_cpu().
	 */
	if (READ_ONCE(table->ents[index]) != val)
		WRITE_ONCE(table->ents[index], val);
}
```
- `index`값은 `hash`에서 마스킹하여 구한다.
- `val`값은 `hash`에서 CPU mask를 빼서 기존에 저장된 CPU ID를 초기화하고, `raw_smp_process_id()` 함수로 현재 실행 중인CPU ID를 저장한다.
- 구한 `index`에 맞는 테이블이 `val`과 다르다면 값을 업데이트한다. 이 경우 락을 잡지 않았으므로 READ_ONCE와 WRITE_ONCE 도중 다른 CPU가 값을 변경할 수도 있다.