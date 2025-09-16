---
Parameter:
- void *
- size_t
- void * __always_unused
- iov_iter *
Return:
- size_t
Location:
- /net/core/datagram.c
---

```c
static size_t simple_copy_to_iter(const void *addr, size_t bytes,
		void *data __always_unused, struct iov_iter *i)
{
	return copy_to_iter(addr, bytes, i);
}
```
[[copy_to_iter()]]

