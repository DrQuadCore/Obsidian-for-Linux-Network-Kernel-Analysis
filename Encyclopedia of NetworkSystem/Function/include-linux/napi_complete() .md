---
Parameter:
  - napi_struct
Return: bool
Location: /include/linux/netdevice.h
---

```c title=napi_complete()
/**
 * napi_complete_done - NAPI processing complete
 * @n: NAPI context
 * @work_done: number of packets processed
 *
 * Mark NAPI processing as complete. Should only be called if poll budget
 * has not been completely consumed.
 * Prefer over napi_complete().
 * Return false if device should avoid rearming interrupts.
 */
bool napi_complete_done(struct napi_struct *n, int work_done);

static inline bool napi_complete(struct napi_struct *n)
{
	return napi_complete_done(n, 0); // [[Encyclopedia of NetworkSystem/Function/net-core/napi_complete_done().md|napi_complete_done()]]
}
```

[[Encyclopedia of NetworkSystem/Function/net-core/napi_complete_done().md|napi_complete_done()]]
