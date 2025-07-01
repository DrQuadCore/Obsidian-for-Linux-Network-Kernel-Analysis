---
Parameter:
  - sk_buff
  - __be32
  - __be32_
  - u8
  - net_device
  - fib_result
Return: int
Location: /net/ipv4/route.c
---
```c
/*
 *  NOTE. We drop all the packets that has local source
 *  addresses, because every properly looped back packet
 *  must have correct destination already attached by output routine.
 *  Changes in the enforced policies must be applied also to
 *  ip_route_use_hint().
 *
 *  Such approach solves two big problems:
 *  1. Not simplex devices are handled properly.
 *  2. IP spoofing attempts are filtered with 100% of guarantee.
 *  called with rcu_read_lock()
 */
  
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                   u8 tos, struct net_device *dev,
                   struct fib_result *res)
{
    struct in_device *in_dev = __in_dev_get_rcu(dev);
    struct flow_keys *flkeys = NULL, _flkeys;
    struct net    *net = dev_net(dev);
    struct ip_tunnel_info *tun_info;
    int     err = -EINVAL;
    unsigned int    flags = 0;
    u32     itag = 0;
    struct rtable   *rth;
    struct flowi4   fl4;
    bool do_cache = true;
  
    /* IP on this device is disabled. */
  
    if (!in_dev)
        goto out;
  
    /* Check for the most weird martians, which can be not detected
     * by fib_lookup.
     */
  
    tun_info = skb_tunnel_info(skb);
    if (tun_info && !(tun_info->mode & IP_TUNNEL_INFO_TX))
        fl4.flowi4_tun_key.tun_id = tun_info->key.tun_id;
    else
        fl4.flowi4_tun_key.tun_id = 0;
    skb_dst_drop(skb);
  
    if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr))
        goto martian_source;
  
    res->fi = NULL;
    res->table = NULL;
    if (ipv4_is_lbcast(daddr) || (saddr == 0 && daddr == 0))
        goto brd_input;
  
    /* Accept zero addresses only to limited broadcast;
     * I even do not know to fix it or not. Waiting for complains :-)
     */
    if (ipv4_is_zeronet(saddr))
        goto martian_source;
  
    if (ipv4_is_zeronet(daddr))
        goto martian_destination;
  
    /* Following code try to avoid calling IN_DEV_NET_ROUTE_LOCALNET(),
     * and call it once if daddr or/and saddr are loopback addresses
     */
    if (ipv4_is_loopback(daddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net))
            goto martian_destination;
    } else if (ipv4_is_loopback(saddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net))
            goto martian_source;
    }
  
    /*
     *  Now we are ready to route packet.
     */
    fl4.flowi4_l3mdev = 0;
    fl4.flowi4_oif = 0;
    fl4.flowi4_iif = dev->ifindex;
    fl4.flowi4_mark = skb->mark;
    fl4.flowi4_tos = tos;
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
    fl4.flowi4_flags = 0;
    fl4.daddr = daddr;
    fl4.saddr = saddr;
    fl4.flowi4_uid = sock_net_uid(net, NULL);
    fl4.flowi4_multipath_hash = 0;
  
    if (fib4_rules_early_flow_dissect(net, skb, &fl4, &_flkeys)) {
        flkeys = &_flkeys;
    } else {
        fl4.flowi4_proto = 0;
        fl4.fl4_sport = 0;
        fl4.fl4_dport = 0;
    }
  
    err = fib_lookup(net, &fl4, res, 0);
    if (err != 0) {
        if (!IN_DEV_FORWARD(in_dev))
            err = -EHOSTUNREACH;
        goto no_route;
    }
  
    if (res->type == RTN_BROADCAST) {
        if (IN_DEV_BFORWARD(in_dev))
            goto make_route;
        /* not do cache if bc_forwarding is enabled */
        if (IPV4_DEVCONF_ALL_RO(net, BC_FORWARDING))
            do_cache = false;
        goto brd_input;
    }


    if (res->type == RTN_LOCAL) {
        err = fib_validate_source(skb, saddr, daddr, tos,
                      0, dev, in_dev, &itag);
        if (err < 0)
            goto martian_source;
        goto local_input;
    }
  
    if (!IN_DEV_FORWARD(in_dev)) {
        err = -EHOSTUNREACH;
        goto no_route;
    }
    if (res->type != RTN_UNICAST)
        goto martian_destination;
  
make_route:
    err = ip_mkroute_input(skb, res, in_dev, daddr, saddr, tos, flkeys);
out:    return err;
  
brd_input:
    if (skb->protocol != htons(ETH_P_IP))
        goto e_inval;
  
    if (!ipv4_is_zeronet(saddr)) {
        err = fib_validate_source(skb, saddr, 0, tos, 0, dev,
                      in_dev, &itag);
        if (err < 0)
            goto martian_source;
    }
    flags |= RTCF_BROADCAST;
    res->type = RTN_BROADCAST;
    RT_CACHE_STAT_INC(in_brd);
  
local_input:
    if (IN_DEV_ORCONF(in_dev, NOPOLICY))
        IPCB(skb)->flags |= IPSKB_NOPOLICY;
  
    do_cache &= res->fi && !itag;
    if (do_cache) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
  
        rth = rcu_dereference(nhc->nhc_rth_input);
        if (rt_cache_valid(rth)) {
            skb_dst_set_noref(skb, &rth->dst);
            err = 0;
            goto out;
        }
    }
  
    rth = rt_dst_alloc(ip_rt_get_dev(net, res),
               flags | RTCF_LOCAL, res->type, false);
    if (!rth)
        goto e_nobufs;
  
    rth->dst.output= ip_rt_bug;
#ifdef CONFIG_IP_ROUTE_CLASSID
    rth->dst.tclassid = itag;
#endif
    rth->rt_is_input = 1;
  
    RT_CACHE_STAT_INC(in_slow_tot);
    if (res->type == RTN_UNREACHABLE) {
        rth->dst.input= ip_error;
        rth->dst.error= -err;
        rth->rt_flags   &= ~RTCF_LOCAL;
    }
  
    if (do_cache) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
  
        rth->dst.lwtstate = lwtstate_get(nhc->nhc_lwtstate);
        if (lwtunnel_input_redirect(rth->dst.lwtstate)) {
            WARN_ON(rth->dst.input == lwtunnel_input);
            rth->dst.lwtstate->orig_input = rth->dst.input;
            rth->dst.input = lwtunnel_input;
        }
        
        if (unlikely(!rt_cache_route(nhc, rth)))
            rt_add_uncached_list(rth);
    }
    skb_dst_set(skb, &rth->dst);
    err = 0;
    goto out;
  
no_route:
    RT_CACHE_STAT_INC(in_no_route);
    res->type = RTN_UNREACHABLE;
    res->fi = NULL;
    res->table = NULL;
    goto local_input;
  
    /*
     *  Do not cache martian addresses: they should be logged (RFC1812)
     */
martian_destination:
    RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
    if (IN_DEV_LOG_MARTIANS(in_dev))
        net_warn_ratelimited("martian destination %pI4 from %pI4, dev %s\n",
                     &daddr, &saddr, dev->name);
#endif
  
e_inval:
    err = -EINVAL;
    goto out;
  
e_nobufs:
    err = -ENOBUFS;
    goto out;
  
martian_source:
    ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
    goto out;
}
```

>중간에 `flow_keys`라는 구조체를 선언하는 것을 볼 수 있다. 이는 패킷을 전부 처리하지 않고, 특정 메타데이터를 뽑아내는 flow dissector라는 기술에 쓰이는 구조체이다.
>다음으로 봐야할 구조체는 `flowi4`이다.
>input / output interface, l3mdev, tos, scope, protocol, flags, tun_key, uid, saddr, daddr, sport, dport, icmp_type ... 등등 많은 필드를 가지고 있다.
>또 다른 구조체로는 `fib_result`가 있다.
>fib란, Forwarding Information Base의 약자로, 3계층에서 포워딩에 필요한 정보들을 가지고 있는 베이스이다. `fib_result`구조체는 다양한 필드를 포함하고 있으며 prefix, prefixlen, nh_sel, type, scope, tclassid, nhc, fib_info타입, fib_table타입, hlist_head타입 등을 포함하고 있다.
>
>본 함수에서 사용되는 "martians"라는 키워드는 '이상한' 이라는 의미를 가진다고 보면 된다.
>함수 코드를 차례로 살펴보자면, 우선 tunnel과 관련된 설정을 해주게 된다. `tun_info` 변수를 확인하여 만약 유효하다면, `fl4`로 선언되어 있는 `flowi4`구조체 에다가 해당 필드를 세팅하게 된다.
>
>그 후 `skb_dst_drop()`함수를 통해 해당 `skb`의 `dst`부분을 드랍하게 된다. 이것은 아마도 앞서 호출한 `tcp_v4_early_demux`를 통해 얻은 `dst_entry` 구조체로 보인다.
>
>추가적으로 확인하는 것은 멀티캐스트와 limited 브로드캐스트의 여부이다. 또한 source와 dest의 addr이 0.0.0.0인 경우도 예외로 하여 `goto`를 사용하고 있었다.
>
>그 후에야 `fl4` 변수를 설정하기 시작하여 패킷을 라우팅할 준비를 하기 시작한다.
>
>그 다음으로 호출하는 함수는 `fib_lookup()`이다. 이 함수는 parameter로 받은 flp에다가 fib 정보를 저장하게 된다. 그리고 `fib_result`를 세팅하게 될 것이다.

--9월 20일 미팅 --
>end-to-end 경로만 살펴 볼 것이므로, `local_input`라벨로 가는 것만 살펴 볼 것이다. 우선 `fib_lookup()`함수를 호출하여 포인터 타입으로 넘겨준 `fib_result`타입의 `res`변수에다가 `type`필드에 해당 패킷이 어디로 가야 할지 enum을 통해 설정하게 되고, 이 값은 `RTN_LOCAL`이 된다. 따라서 `local_input`라벨로 가게 되는 것이다. 이후 `dst_entry` 구조체를 세팅하고 함수가 리턴된다.


[[fib_lookup()]]