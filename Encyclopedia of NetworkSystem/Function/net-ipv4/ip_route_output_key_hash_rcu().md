---
Parameter:
  - net
  - flowi4
  - fib_result
  - sk_buff
Return: rtable
Location: /net/ipv4/route.c
---
```c
struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
					    struct fib_result *res,
					    const struct sk_buff *skb)
{
	struct net_device *dev_out = NULL;
	int orig_oif = fl4->flowi4_oif; // output interface
	unsigned int flags = 0;
	struct rtable *rth;
	int err;

	if (fl4->saddr) {
		if (ipv4_is_multicast(fl4->saddr) ||
		    ipv4_is_lbcast(fl4->saddr) ||
		    ipv4_is_zeronet(fl4->saddr)) {
			rth = ERR_PTR(-EINVAL);
			goto out;
		}

		rth = ERR_PTR(-ENETUNREACH);

		/* I removed check for oif == dev_out->oif here.
		 * It was wrong for two reasons:
		 * 1. ip_dev_find(net, saddr) can return wrong iface, if saddr
		 *    is assigned to multiple interfaces.
		 * 2. Moreover, we are allowed to send packets with saddr
		 *    of another iface. --ANK
		 */

		if (fl4->flowi4_oif == 0 &&
		    (ipv4_is_multicast(fl4->daddr) ||
		     ipv4_is_lbcast(fl4->daddr))) {
			/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
			dev_out = __ip_dev_find(net, fl4->saddr, false);
			if (!dev_out)
				goto out;

			/* Special hack: user can direct multicasts
			 * and limited broadcast via necessary interface
			 * without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
			 * This hack is not just for fun, it allows
			 * vic,vat and friends to work.
			 * They bind socket to loopback, set ttl to zero
			 * and expect that it will work.
			 * From the viewpoint of routing cache they are broken,
			 * because we are not allowed to build multicast path
			 * with loopback source addr (look, routing cache
			 * cannot know, that ttl is zero, so that packet
			 * will not leave this host and route is valid).
			 * Luckily, this hack is good workaround.
			 */

			fl4->flowi4_oif = dev_out->ifindex;
			goto make_route;
		}

		if (!(fl4->flowi4_flags & FLOWI_FLAG_ANYSRC)) {
			/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
			if (!__ip_dev_find(net, fl4->saddr, false))
				goto out;
		}
	}


	if (fl4->flowi4_oif) {
		dev_out = dev_get_by_index_rcu(net, fl4->flowi4_oif);
		rth = ERR_PTR(-ENODEV);
		if (!dev_out)
			goto out;

		/* RACE: Check return value of inet_select_addr instead. */
		if (!(dev_out->flags & IFF_UP) || !__in_dev_get_rcu(dev_out)) {
			rth = ERR_PTR(-ENETUNREACH);
			goto out;
		}
		if (ipv4_is_local_multicast(fl4->daddr) ||
		    ipv4_is_lbcast(fl4->daddr) ||
		    fl4->flowi4_proto == IPPROTO_IGMP) {
			if (!fl4->saddr)
				fl4->saddr = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			goto make_route;
		}
		if (!fl4->saddr) {
			if (ipv4_is_multicast(fl4->daddr))
				fl4->saddr = inet_select_addr(dev_out, 0,
							      fl4->flowi4_scope);
			else if (!fl4->daddr)
				fl4->saddr = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);
		}
	}

	if (!fl4->daddr) {
		fl4->daddr = fl4->saddr;
		if (!fl4->daddr)
			fl4->daddr = fl4->saddr = htonl(INADDR_LOOPBACK);
		dev_out = net->loopback_dev;
		fl4->flowi4_oif = LOOPBACK_IFINDEX;
		res->type = RTN_LOCAL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	err = fib_lookup(net, fl4, res, 0);
	if (err) {
		res->fi = NULL;
		res->table = NULL;
		if (fl4->flowi4_oif &&
		    (ipv4_is_multicast(fl4->daddr) || !fl4->flowi4_l3mdev)) {
			/* Apparently, routing tables are wrong. Assume,
			 * that the destination is on link.
			 *
			 * WHY? DW.
			 * Because we are allowed to send to iface
			 * even if it has NO routes and NO assigned
			 * addresses. When oif is specified, routing
			 * tables are looked up with only one purpose:
			 * to catch if destination is gatewayed, rather than
			 * direct. Moreover, if MSG_DONTROUTE is set,
			 * we send packet, ignoring both routing tables
			 * and ifaddr state. --ANK
			 *
			 *
			 * We could make it even if oif is unknown,
			 * likely IPv6, but we do not.
			 */

			if (fl4->saddr == 0)
				fl4->saddr = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			res->type = RTN_UNICAST;
			goto make_route;
		}
		rth = ERR_PTR(err);
		goto out;
	}

	if (res->type == RTN_LOCAL) {
		if (!fl4->saddr) {
			if (res->fi->fib_prefsrc)
				fl4->saddr = res->fi->fib_prefsrc;
			else
				fl4->saddr = fl4->daddr;
		}

		/* L3 master device is the loopback for that domain */
		dev_out = l3mdev_master_dev_rcu(FIB_RES_DEV(*res)) ? :
			net->loopback_dev;

		/* make sure orig_oif points to fib result device even
		 * though packet rx/tx happens over loopback or l3mdev
		 */
		orig_oif = FIB_RES_OIF(*res);

		fl4->flowi4_oif = dev_out->ifindex;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

	fib_select_path(net, res, fl4, skb);

	dev_out = FIB_RES_DEV(*res);

make_route:
	rth = __mkroute_output(res, fl4, orig_oif, dev_out, flags);

out:
	return rth;
}
```

---
>source address 관련 확인

source address가 정말 source address로 사용할 수 있는 IPv4 주소인지 검사한다. 

```c
struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
					    struct fib_result *res,
					    const struct sk_buff *skb)
{
	struct net_device *dev_out = NULL;
	int orig_oif = fl4->flowi4_oif; // output interface
	unsigned int flags = 0;
	struct rtable *rth;
	int err;
	
	if (fl4->saddr) {
		if (ipv4_is_multicast(fl4->saddr) || // 멀티캐스트 주소 범위
		    ipv4_is_lbcast(fl4->saddr) || // limited 브로드캐스트 주소 
		    ipv4_is_zeronet(fl4->saddr)) { // 0.0.0.0/8 범위의 주소 
			rth = ERR_PTR(-EINVAL); 
			goto out;
		}
```

source 주소는 존재하나, 사용자가 output interface를 명시하지 않았고, destination 주소가 멀티캐스트 주소이거나 limited 브로드캐스트 주소일 경우에 실행되는 로직이다. __ ip_dev_find() 함수로 먼저 source address를 담당하는 NIC을 찾아서 자동으로 그 NIC을 output interface로 삼는다. 

```c
		if (fl4->flowi4_oif == 0 &&
		    (ipv4_is_multicast(fl4->daddr) ||
		     ipv4_is_lbcast(fl4->daddr))) {
			/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
			dev_out = __ip_dev_find(net, fl4->saddr, false);
			if (!dev_out)
				goto out;

			fl4->flowi4_oif = dev_out->ifindex;
			goto make_route;
		}
```

__ ip_dev_find()는 FLOWI_FLAG_ANYSRC flag가 꺼져 있을 때, source 주소를 가진 NIC이 실제로 존재하는지 찾아주는 함수이다. FLOWI_FLAG_ANYSRC가 켜져 있다는 말은, source 주소가 로컬 NIC에 없어도 허용한다는 의미이다. 
(참고 - transparent 소켓은 NIC에 없는 IP도 사용할 수 있도록 허용하는 소켓이다. [Transparent proxy support — The Linux Kernel documentation](https://www.kernel.org/doc/html/v5.8/networking/tproxy.html) )

```c

		if (!(fl4->flowi4_flags & FLOWI_FLAG_ANYSRC)) {
			/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
			if (!__ip_dev_find(net, fl4->saddr, false))
				goto out;
		}
	}
```


>output intereface 관련 확인

output inferface가 지정돼 있으면, 그 NIC이 실제로 존재하는지 먼저 확인한다. 존재한다면 NIC이 UP 상태인지, IPv4 주소 리스트를 갖고 있는 구조체(dev->ip_ptr)를 갖고 있는지 확인한다. 

```c
	if (fl4->flowi4_oif) {
		dev_out = dev_get_by_index_rcu(net, fl4->flowi4_oif);
		rth = ERR_PTR(-ENODEV);
		if (!dev_out)
			goto out;

		/* RACE: Check return value of inet_select_addr instead. */
		if (!(dev_out->flags & IFF_UP) || !__in_dev_get_rcu(dev_out)) {
			rth = ERR_PTR(-ENETUNREACH);
			goto out;
		}
```

output interface는 지정돼 있지만, destination 주소가 로컬 멀티캐스트 혹은 limited 브로드캐스트이거나 IGMP 프로토콜을 사용할 때는 source 주소를 확인한다. saddr이 지정돼 있지 않은 경우엔 그 NIC(dev_out)이 가진 IPv4 주소 중 RT_SCOPE_LINK 범위의 주소를 source 주소로 설정한다. 

```c
		if (ipv4_is_local_multicast(fl4->daddr) ||
		    ipv4_is_lbcast(fl4->daddr) ||
		    fl4->flowi4_proto == IPPROTO_IGMP) {
			if (!fl4->saddr)
				fl4->saddr = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK); // [[inet_select_addr()]]
			goto make_route;
		}
```

saddr이 설정돼 있지 않은 상황에서 destination 주소가 멀티캐스트 주소라면 flowi4_scope에 맞는 주소를, daddr이 설정돼 있지 않다면 RT_SCOPE_HOST 범위에 맞는 주소를 source로 선택한다.

```c
		if (!fl4->saddr) {
			if (ipv4_is_multicast(fl4->daddr))
				fl4->saddr = inet_select_addr(dev_out, 0,
							      fl4->flowi4_scope);
			else if (!fl4->daddr)
				fl4->saddr = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);
		}
	}
```

```c
/* rtm_scope 

   Really it is not scope, but sort of distance to the destination.
   NOWHERE are reserved for not existing destinations, HOST is our
   local addresses, LINK are destinations, located on directly attached
   link and UNIVERSE is everywhere in the Universe.

   Intermediate values are also possible f.e. interior routes
   could be assigned a value between UNIVERSE and LINK.
*/

enum rt_scope_t {
	RT_SCOPE_UNIVERSE=0,
/* User defined values  */
	RT_SCOPE_SITE=200, 
	RT_SCOPE_LINK=253,
	RT_SCOPE_HOST=254,
	RT_SCOPE_NOWHERE=255
};
```


>destination address 관련 확인

daddr이 0이라면 destination address가 없는 패킷이므로, 해당 패킷을 자신으로 보내는 loopback 패킷으로 보고 daddr을 saddr로 설정한다. 

```c
	if (!fl4->daddr) {
		fl4->daddr = fl4->saddr;
		if (!fl4->daddr)
			fl4->daddr = fl4->saddr = htonl(INADDR_LOOPBACK);
		dev_out = net->loopback_dev;
		fl4->flowi4_oif = LOOPBACK_IFINDEX;
		res->type = RTN_LOCAL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}
```

> fib_lookup 수행