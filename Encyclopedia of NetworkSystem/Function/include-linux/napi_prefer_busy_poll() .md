---
Parameter:
  - napi_struct
Return: bool
Location: /include/linux/netdevice.h
---

```c title=napi_prefer_busy_poll()
static inline bool napi_prefer_busy_poll(struct napi_struct *n)
{
	return test_bit(NAPI_STATE_PREFER_BUSY_POLL, &n->state);
}
```

> napi_struct의 state 변수가 NAPI_STATE_PREFER_BUSY_POLL이 셋팅 되어있는지 test_bit을 하게 되는 함수