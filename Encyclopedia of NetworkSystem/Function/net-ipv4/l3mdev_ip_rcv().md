```c
static inline
struct sk_buff *l3mdev_ip_rcv(struct sk_buff *skb)
{
	return l3mdev_l3_rcv(skb, AF_INET);
}
```
l3mdev_l3_rcv() 함수를 호출한다.
```c
static inline
struct sk_buff *l3mdev_l3_rcv(struct sk_buff *skb, u16 proto)
{
	struct net_device *master = NULL;

	if (netif_is_l3_slave(skb->dev))
		master = netdev_master_upper_dev_get_rcu(skb->dev);
	else if (netif_is_l3_master(skb->dev) ||
		 netif_has_l3_rx_handler(skb->dev))
		master = skb->dev;

	if (master && master->l3mdev_ops->l3mdev_l3_rcv)
		skb = master->l3mdev_ops->l3mdev_l3_rcv(master, skb, proto);

	return skb;
}
```

skb의 device network interface가 l3_slave인 경우, 

>L3 Slave는 Layer 3 네트워크에서 상위 장치나 네트워크에 종속된 장치를 의미한다. 일반적으로 L3 네트워크에서 패킷 라우팅을 처리하는 상위 장치가 L3 마스터 역할을 하고, 그 아래에서 패킷을 전달받아 처리하는 장치가 L3 Slave 역할을 한다. L3 Slave는 마스터 장치에 종속되어 동작하며, 여러 개의 Slave가 하나의 마스터 아래에서 동작할 수 있다. 이를 통해 네트워크 트래픽을 효율적으로 관리하고 분산 처리할 수 있다. 

```c
static inline
struct sk_buff *l3mdev_ip_rcv(struct sk_buff *skb)
{
	return skb;
}
```