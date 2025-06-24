---
Return:
  - void
Location: /include/net/gro.h
Parameter:
  - napi_struct
  - sk_buff
  - int
---
>해당 `skb`를 `napi->rx_list`에 새로이 올리게 된다. 여기서 `segs`는 `skb의 cb의 count`값인데, 이는 aggregated된 packet의 수 이다. 만약 이 rx_count의 종합이 `net_hotdata`에서 가져온 `gro_normal_batch`보다 크거나 같게 된다면 `gro_normal_list()`함수를 호출하게 된다. 그게 아니라면 그냥 넘어가게 된다. 그렇다면, 

[[김기수/산협 프로젝트 2/백서 제작용/gro_normal_list()]]