---
Parameter:
  - napi_struct
  - sk_buff
Return: void
Location: /net/core/gro.c
---

```c title=napi_gro_complete()
static void napi_gro_complete(struct napi_struct *napi, struct sk_buff *skb)
{
	struct list_head *head = &net_hotdata.offload_base;
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = INDIRECT_CALL_INET(ptype->callbacks.gro_complete,
					 ipv6_gro_complete, inet_gro_complete,
					 skb, 0); // [[Encyclopedia of NetworkSystem/Function/net-ipv6/ipv6_gro_complete().md|ipv6_gro_complete()]] [[Encyclopedia of NetworkSystem/Function/net-ipv4/inet_gro_complete().md|inet_gro_complete()]]
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);
		kfree_skb(skb);
		return;
	}

out:
	gro_normal_one(napi, skb, NAPI_GRO_CB(skb)->count); // [[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_one().md|gro_normal_one()]]
}

static void __napi_gro_flush_chain(struct napi_struct *napi, u32 index,
				   bool flush_old)
{
	struct list_head *head = &napi->gro_hash[index].list;
	struct sk_buff *skb, *p;

	list_for_each_entry_safe_reverse(skb, p, head, list) {
		if (flush_old && NAPI_GRO_CB(skb)->age == jiffies)
			return;
		skb_list_del_init(skb);
		napi_gro_complete(napi, skb);
		napi->gro_hash[index].count--;
	}

	if (!napi->gro_hash[index].count)
		__clear_bit(index, &napi->gro_bitmask);
}
```

[[Encyclopedia of NetworkSystem/Function/net-ipv6/ipv6_gro_complete().md|ipv6_gro_complete()]] 
[[Encyclopedia of NetworkSystem/Function/net-ipv4/inet_gro_complete().md|inet_gro_complete()]]
[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_one().md|gro_normal_one()]]

> IP 버전에 따라 서로 다른 gro_complet를 callback할 수 있도록 하는 함수이다. 아니라면 만약 skb→count가 1이라면 해당 gro_list는 합치지 않았으므로 out 라벨로 건너뛰어 바로 gro_normal_one()함수를 호출하게 된다. 아니라면 head를 돌면서 각각의 gro_complete를 실행하게 된다. 이후 최종적으로 `gro_normal_one()` 함수를 실행하게 된다.