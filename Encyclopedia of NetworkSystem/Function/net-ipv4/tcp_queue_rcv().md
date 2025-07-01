```c
static int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb,
				      bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

	eaten = (tail &&
		 tcp_try_coalesce(sk, tail,
				  skb, fragstolen)) ? 1 : 0;
	tcp_rcv_nxt_update(tcp_sk(sk), TCP_SKB_CB(skb)->end_seq);
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		skb_set_owner_r(skb, sk);
	}
	return eaten;
}
```

`tcp_try_coalesce()`를 시도한다. 성공할 경우 리턴하고
\_\_skb_queue_tail()로 sk_receive_queue에 skb를 추가한다

tcp_try_coalesce()도 추가적인 조건을 확인하고 skb_try_coalesce()를 실행한다. 

>return 할 `eaten` 변수를 선언하고, `sk_buff`타입의 `tail` 변수를 선언하게 되는데, 이는 해당 소켓의 `sk_receive_queue`에서 마지막 skb를 가져오는 것이다.이때, 이 마지막 skb와 새롭게 들어온 skb를 합치기 위해 `tcp_try_coalesce()`함수를 호출하게 된다. 만약 합치지 못하였다면, 해당 소켓의 `sk_receive_queue`에다가 그 skb를 새로 추가하게 되고, `skb_set_owner_r()`함수를 호출하게 된다.
>
>이후 `eaten`을 리턴하게 된다. 

[[tcp_try_coalesce()]]
