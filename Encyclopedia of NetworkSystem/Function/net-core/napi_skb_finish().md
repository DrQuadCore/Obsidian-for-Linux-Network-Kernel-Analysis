---
Parameter:
  - napi_struct
  - sk_buff
  - gro_result_t
Return: gro_result_t
Location: /net/core/gro.c
---

```c title=napi_skb_finish()
static gro_result_t napi_skb_finish(struct napi_struct *napi,
				    struct sk_buff *skb,
				    gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
		gro_normal_one(napi, skb, 1);
		break;

	case GRO_MERGED_FREE:
		if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)
			napi_skb_free_stolen_head(skb);
		else if (skb->fclone != SKB_FCLONE_UNAVAILABLE)
			__kfree_skb(skb);
		else
			__napi_kfree_skb(skb, SKB_CONSUMED);
		break;

	case GRO_HELD:
	case GRO_MERGED:
	case GRO_CONSUMED:
		break;
	}

	return ret;
}
```

> 위의 `dev_gro_receive()` 함수의 return 값을 바탕으로 switch문을 통해 뒤 처리를 하는 함수. GRO_~~ enum을 사용함.