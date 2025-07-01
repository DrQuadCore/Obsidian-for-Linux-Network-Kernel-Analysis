---
Location: /include/linux/netdevice.h
sticker: ""
---

```c title=packet_offload
struct packet_offload {
	__be16			 type;	/* This is really htons(ether_type). */
	u16			 priority;
	struct offload_callbacks callbacks;
	struct list_head	 list;
};
```
