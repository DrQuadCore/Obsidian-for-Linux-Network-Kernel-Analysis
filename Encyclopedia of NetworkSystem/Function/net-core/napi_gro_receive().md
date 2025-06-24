---
Parameter:
  - napi_struct
  - sk_buff
Return: gro_result_t
Location: /net/core/gro.c
---

```c title=napi_gro_receive()
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	gro_result_t ret; // [[Encyclopedia of NetworkSystem/Struct/include-linux/gro_result.md|gro_result_t]]

	skb_mark_napi_id(skb, napi);
	trace_napi_gro_receive_entry(skb);

	skb_gro_reset_offset(skb, 0);

	ret = napi_skb_finish(napi, skb, dev_gro_receive(napi, skb));
	trace_napi_gro_receive_exit(ret); // [[Encyclopedia of NetworkSystem/Function/net-core/napi_skb_finish().md|napi_skb_finish()]] [[Encyclopedia of NetworkSystem/Function/net-core/dev_gro_receive().md|dev_gro_receive()]]

	return ret;
}
EXPORT_SYMBOL(napi_gro_receive);
```

[[Encyclopedia of NetworkSystem/Struct/include-linux/gro_result.md|gro_result_t]]
[[Encyclopedia of NetworkSystem/Function/net-core/napi_skb_finish().md|napi_skb_finish()]] 
[[Encyclopedia of NetworkSystem/Function/net-core/dev_gro_receive().md|dev_gro_receive()]]

> `dev_gro_receive()` 함수에서 skb와 napi를 통해 실질적으로 gro를 처리하게 됨. 전후로 기타작업을 하는 함수들이 호출되고 있고, `napi_skb_finish()`함수를 `dev_gro_receive()` 함수의 return 값을 인수로 하여 호출하게 됨. 