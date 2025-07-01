```c
static struct sock *tcp_v4_cookie_check(struct sock *sk, struct sk_buff *skb)
{
#ifdef CONFIG_SYN_COOKIES
	const struct tcphdr *th = tcp_hdr(skb);

	if (!th->syn)
		sk = cookie_v4_check(sk, skb);
#endif
	return sk;
}
```

```c
/* On input, sk is a listener.
 * Output is listener if incoming packet would not create a child
 *           NULL if memory could not be allocated.
 */
struct sock *cookie_v4_check(struct sock *sk, struct sk_buff *skb)
{
	struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
	const struct tcphdr *th = tcp_hdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_request_sock *ireq;
	struct net *net = sock_net(sk);
	struct request_sock *req;
	struct sock *ret = sk;
	struct flowi4 fl4;
	struct rtable *rt;
	__u8 rcv_wscale;
	int full_space;
	SKB_DR(reason);

	if (!READ_ONCE(net->ipv4.sysctl_tcp_syncookies) ||
	    !th->ack || th->rst)
		goto out;

	if (cookie_bpf_ok(skb)) {
		req = cookie_bpf_check(sk, skb);
	} else {
		req = cookie_tcp_check(net, sk, skb);
		if (IS_ERR(req))
			goto out;
	}
	if (!req) {
		SKB_DR_SET(reason, NO_SOCKET);
		goto out_drop;
	}

	ireq = inet_rsk(req);

	sk_rcv_saddr_set(req_to_sk(req), ip_hdr(skb)->daddr);
	sk_daddr_set(req_to_sk(req), ip_hdr(skb)->saddr);

	/* We throwed the options of the initial SYN away, so we hope
	 * the ACK carries the same options again (see RFC1122 4.2.3.8)
	 */
	RCU_INIT_POINTER(ireq->ireq_opt, tcp_v4_save_options(net, skb));

	if (security_inet_conn_request(sk, skb, req)) {
		SKB_DR_SET(reason, SECURITY_HOOK);
		goto out_free;
	}

	tcp_ao_syncookie(sk, skb, req, AF_INET);

	/*
	 * We need to lookup the route here to get at the correct
	 * window size. We should better make sure that the window size
	 * hasn't changed since we received the original syn, but I see
	 * no easy way to do this.
	 */
	flowi4_init_output(&fl4, ireq->ir_iif, ireq->ir_mark,
			   ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
			   IPPROTO_TCP, inet_sk_flowi_flags(sk),
			   opt->srr ? opt->faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, th->source, th->dest, sk->sk_uid);
	security_req_classify_flow(req, flowi4_to_flowi_common(&fl4));
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		SKB_DR_SET(reason, IP_OUTNOROUTES);
		goto out_free;
	}

	/* Try to redo what tcp_v4_send_synack did. */
	req->rsk_window_clamp = tp->window_clamp ? :dst_metric(&rt->dst, RTAX_WINDOW);
	/* limit the window selection if the user enforce a smaller rx buffer */
	full_space = tcp_full_space(sk);
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (req->rsk_window_clamp > full_space || req->rsk_window_clamp == 0))
		req->rsk_window_clamp = full_space;

	tcp_select_initial_window(sk, full_space, req->mss,
				  &req->rsk_rcv_wnd, &req->rsk_window_clamp,
				  ireq->wscale_ok, &rcv_wscale,
				  dst_metric(&rt->dst, RTAX_INITRWND));

	/* req->syncookie is set true only if ACK is validated
	 * by BPF kfunc, then, rcv_wscale is already configured.
	 */
	if (!req->syncookie)
		ireq->rcv_wscale = rcv_wscale;
	ireq->ecn_ok &= cookie_ecn_ok(net, &rt->dst);

	ret = tcp_get_cookie_sock(sk, skb, req, &rt->dst);
	/* ip_queue_xmit() depends on our flow being setup
	 * Normal sockets get it right from inet_csk_route_child_sock()
	 */
	if (!ret) {
		SKB_DR_SET(reason, NO_SOCKET);
		goto out_drop;
	}
	inet_sk(ret)->cork.fl.u.ip4 = fl4;
out:
	return ret;
out_free:
	reqsk_free(req);
out_drop:
	kfree_skb_reason(skb, reason);
	return NULL;
}
```