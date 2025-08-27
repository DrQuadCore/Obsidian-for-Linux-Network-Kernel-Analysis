```c title=tcp_child_process()
// net/ipv4/tcp_minisock.c
/*
 * Queue segment on the new socket if the new socket is active,
 * otherwise we just shortcircuit this and continue with
 * the new socket.
 *
 * For the vast majority of cases child->sk_state will be TCP_SYN_RECV
 * when entering. But other states are possible due to a race condition
 * where after __inet_lookup_established() fails but before the listener
 * locked is obtained, other packets cause the same connection to
 * be created.
 */

enum skb_drop_reason tcp_child_process(struct sock *parent, struct sock *child,
				       struct sk_buff *skb)
	__releases(&((child)->sk_lock.slock))
{
	enum skb_drop_reason reason = SKB_NOT_DROPPED_YET;
	int state = child->sk_state;

	/* record sk_napi_id and sk_rx_queue_mapping of child. */
	// 자식 소켓에 패킷 정보 기록
	sk_mark_napi_id_set(child, skb);

	tcp_segs_in(tcp_sk(child), skb);
	// 소켓 상태 확인 후 분기
	if (!sock_owned_by_user(child)) {
		// 빠른 처리
		reason = tcp_rcv_state_process(child, skb);
		/* Wakeup parent, send SIGIO */
		// 상태가 바뀌었으면 부모 소켓에게 알림
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent);
	} else {
		/* Alas, it is possible again, because we do lookup
		 * in main socket hash table and lock on listening
		 * socket does not protect us more.
		 */
		// 느린 처리
		__sk_add_backlog(child, skb);
	}

	// 리소스 정리
	bh_unlock_sock(child);
	sock_put(child);
	return reason;
}
EXPORT_SYMBOL(tcp_child_process);
```
3-way handshake가 완료되어 자식 소켓이 생성된 패킷을 자식 소켓으로 전달한다. 자식 소켓에 패킷 정보를 기록하고, 빠른 경로로 `tcp_rcv_state_process()`함수를 호출하거나, 아니면 느린 경로로 `__sk_add_backlog()`함수를 호출한다.