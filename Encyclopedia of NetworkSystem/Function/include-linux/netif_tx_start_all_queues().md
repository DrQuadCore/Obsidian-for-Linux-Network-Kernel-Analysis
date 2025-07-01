---
Parameter:
  - net_device
Return: void
Location: /include/linux/netdevice.h
---

```c title=netif_tx_start_all_queues()
static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_start_queue(txq);
	}
}
```
