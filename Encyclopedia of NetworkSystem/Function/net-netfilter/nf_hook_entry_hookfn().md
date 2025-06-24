```c
static inline int
nf_hook_entry_hookfn(const struct nf_hook_entry *entry, struct sk_buff *skb,
		     struct nf_hook_state *state)
{
	return entry->hook(entry->priv, skb, state);
}
```

>hook entry 에 있는 함수를 실행한다.

https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
https://hayz.tistory.com/entry/번역-Iptables-및-Netfilter-구조에-대한-심층분석
참고자료