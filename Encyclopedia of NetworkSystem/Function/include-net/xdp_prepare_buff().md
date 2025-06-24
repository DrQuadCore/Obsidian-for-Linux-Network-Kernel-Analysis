---
Parameter:
  - xdp_buff
  - char
  - int
  - bool
Return: void
Location: /include/net/xdp.h
---

```c title=xdp_prepare_buff()
static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

	xdp->data_hard_start = hard_start;
	xdp->data = data;
	xdp->data_end = data + data_len;
	xdp->data_meta = meta_valid ? data : data + 1;
}
```

> 주어진 xdp 포인터에다가 hard_start, data, data_end, data_meta를 넣어서 준비시켜준다.
