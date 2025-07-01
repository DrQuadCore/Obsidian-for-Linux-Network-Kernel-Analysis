```C
/**
 * sk_wait_data - wait for data to arrive at sk_receive_queue
 * @sk:    sock to wait on
 * @timeo: for how long
 * @skb:   last skb seen on sk_receive_queue
 *
 * Now socket state including sk->sk_err is changed only under lock,
 * hence we may omit checks after joining wait queue.
 * We check receive queue before schedule() only as optimization;
 * it is very likely that release_sock() added new data.
 */
int sk_wait_data(struct sock *sk, long *timeo, const struct sk_buff *skb)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, timeo, skb_peek_tail(&sk->sk_receive_queue) != skb, &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return rc;
}```