```c
/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
static struct ipq *ip_find(struct net *net, struct iphdr *iph,
			   u32 user, int vif)
{
	struct frag_v4_compare_key key = {
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.user = user,
		.vif = vif,
		.id = iph->id,
		.protocol = iph->protocol,
	};
	struct inet_frag_queue *q;

	q = inet_frag_find(net->ipv4.fqdir, &key);
	if (!q)
		return NULL;

	return container_of(q, struct ipq, q);
}
```

>`inet_frag_find()`함수를 통해 해당하는 `inet_frag_queue`타입의 구조체 변수를 가져오고, 이를 `container_of()`함수를 통해 이를 가지고 있는 `ipq` 구조체를 리턴하게 된다. 
>
>이 때 `inet_frag_find()`함수를 간단하게 설명하자면, `rhashtable_lookup()`함수를 호출하여 유효한 `inet_frag_queue`를 가져오게 된다. 이는 hash_table을 뒤지게 되고, 이 때 `net->ipv4`의 `fqdir`이라는 멤버변수를 가져온다. 이는 frag queue directory로, frag queue를 관리하는 구조체이다. 이 구조체 안에는 `rhashtable`이라는 멤버변수를 가지고 있는데, 이를 바탕으로 lookup이 진행되는 것이다.