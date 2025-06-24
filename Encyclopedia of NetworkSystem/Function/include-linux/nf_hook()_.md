---
Parameter:
  - u_int8_t
  - unsigned int
  - net
  - sock
  - sk_buff
  - net_device
  - net_device_
  - int (*okfn)(struct net *, struct sock *, struct sk_buff *)
Return: int
Location: /include/linux/netfilter.h
---
```c
/**
* nf_hook - call a netfilter hook
*
* Returns 1 if the hook has allowed the packet to pass. The function
* okfn must be invoked by the caller in this case. Any other return
* value indicates the packet has been consumed by the hook.
*/
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
				struct sock *sk, struct sk_buff *skb,
				struct net_device *indev, struct net_device *outdev,
				int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	struct nf_hook_entries *hook_head = NULL;
	int ret = 1;
  
#ifdef CONFIG_JUMP_LABEL
	if (__builtin_constant_p(pf) &&
		__builtin_constant_p(hook) &&
		!static_key_false(&nf_hooks_needed[pf][hook]))
		return 1;
#endif
	  
	rcu_read_lock();
	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
		break;
	case NFPROTO_IPV6:
		hook_head = rcu_dereference(net->nf.hooks_ipv6[hook]);
		break;
	case NFPROTO_ARP:
#ifdef CONFIG_NETFILTER_FAMILY_ARP
		if (WARN_ON_ONCE(hook >= ARRAY_SIZE(net->nf.hooks_arp)))
			break;
		hook_head = rcu_dereference(net->nf.hooks_arp[hook]);
#endif
		break;
	case NFPROTO_BRIDGE:
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
		hook_head = rcu_dereference(net->nf.hooks_bridge[hook]);
#endif
		break;
	default:
		WARN_ON_ONCE(1);
		break;
}
  
if (hook_head) {
struct nf_hook_state state;
  
nf_hook_state_init(&state, hook, pf, indev, outdev,
sk, net, okfn);
  
ret = nf_hook_slow(skb, &state, hook_head, 0);
}
rcu_read_unlock();
  
return ret;
}
```

>주어진 protocol flag를 통해서 해당하는 `hook_head`를 가져오고, `nf_hook_state`타입의 `state`를 초기화 한 뒤, 이를 가지고 `nf_hook_slow()`함수를  실행하게 된다. 여기서 초기화하는 함수는 간단하다. `nf_hook_state`타입의 변수에 `hook` int와 pf, indev, outdev, sk, net, okfn 등을 주어진 parameter에서 가져와서 설정하게 된다. 
>그리고 마지막으로 `nf_hook_slow()`함수에서 나온 결과를 반환하게 된다.

---

>CONFIG_JUMP_LABEL이 활성화되어 있는 경우에 실행되는 코드. return value가 1이면 hook이 pkt
>을 지나가게 허용했다는 뜻이다. 아래의 추가적인 작업 없이 빠르게 처리하는 경우로 보인다. 

>protocol family 에 맞는 hook을 실행해주기 위해 switch문을 사용한다. 
>ipv4, ipv6, arp, bridge, default로 나누어져있다.
>각자 networking namespace에 저장되어있는 hook list를 코드의 가장 위에 있던 hook_head에 
>넣어준다. 
>wtf is networking namespace net??

>hook head에 protocol에 맞는  hook list를 저장하는 데 성공하면 `nf_hook_state_init()`를 실행
>이후 `nf_hook_slow()`를 실행하고 그 결과값을 리턴한다. pkt이 hook을 지나가는데 성공하면 1을
>리턴하고 그 외는 hook 이 pkt을 consume 했다는 의미이다. 

[[nf_hook_slow()]]

```c
struct nf_hook_entries {
	u16				num_hook_entries;
	/* padding */
	struct nf_hook_entry		hooks[];

	/* trailer: pointers to original orig_ops of each hook,
	 * followed by rcu_head and scratch space used for freeing
	 * the structure via call_rcu.
	 *
	 *   This is not part of struct nf_hook_entry since its only
	 *   needed in slow path (hook register/unregister):
	 * const struct nf_hook_ops     *orig_ops[]
	 *
	 *   For the same reason, we store this at end -- its
	 *   only needed when a hook is deleted, not during
	 *   packet path processing:
	 * struct nf_hook_entries_rcu_head     head
	 */
};
```