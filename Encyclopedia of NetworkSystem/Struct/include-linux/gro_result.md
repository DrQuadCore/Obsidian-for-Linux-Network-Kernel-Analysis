---
Location: /include/linux/netdevice.h
sticker: ""
---

```c title=gro_result
enum gro_result {
	GRO_MERGED,
	GRO_MERGED_FREE,
	GRO_HELD,
	GRO_NORMAL,
	GRO_CONSUMED,
};
typedef enum gro_result gro_result_t;
```

