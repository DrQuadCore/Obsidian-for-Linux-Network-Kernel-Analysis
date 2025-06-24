---
Parameter:
  - sk_buff
  - nf_hook_state
  - nf_hook_entries
  - unsigned int
Return: int
Location: net/netfilter/core.c
---
```c
/* Returns 1 if okfn() needs to be executed by the caller,
 * -EPERM for NF_DROP, 0 otherwise.  Caller must hold rcu_read_lock. */
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
		 const struct nf_hook_entries *e, unsigned int s)
{
	unsigned int verdict;
	int ret;

	for (; s < e->num_hook_entries; s++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			break;
		case NF_DROP:
			kfree_skb_reason(skb,
					 SKB_DROP_REASON_NETFILTER_DROP);
			ret = NF_DROP_GETERR(verdict);
			if (ret == 0)
				ret = -EPERM;
			return ret;
		case NF_QUEUE:
			ret = nf_queue(skb, state, s, verdict);
			if (ret == 1)
				continue;
			return ret;
		case NF_STOLEN:
			return NF_DROP_GETERR(verdict);
		default:
			WARN_ON_ONCE(1);
			return 0;
		}
	}

	return 1;
}
```

>이전 함수에 추가했었던 hook_entries에서 하나씩 꺼내서 `nf_hook_entry_hookfn()`에 실행한다. 그리고 그 결과를 가지고 `switch`문이 돌아가는데, 만약 `NF_QUEUE`인 경우 `nf_queue()`함수를 실행하고 아니면 각자 적당한 처리를 하고 넘어가게 된다.

여기서 verdict 판결이 나오는데, 이 값에 따라서 실행되는 코드가 달라진다. 
(accept, drop, queue, stolen)
accept 될 경우, pkt이 위의 stack에 전달이 되었고 1을 리턴해서 성공했음을 알린다.
- NF_DROP(0) : 패킷을 폐기되고 더 이상 처리되지 않는다.
- NF_ACCEPT(1) : 패킷이 커널 네트워크 스택에서 계속 이동한다.
- NF_STOLEN : 패킷은 훅 함수로 처리되어 이동하지 않는다.
- NF_QUEUE : userspace에서 처리되기 위해 queue된다. iptable, nftable과 같은 daemon에서 실행
- NF_REPEAT : pkt이 동일한 hook point 로 re-inject 재실행? 되어서 다시 처리가 된다. 

[[nf_hook_entry_hookfn()]]
