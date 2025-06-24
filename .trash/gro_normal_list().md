---
Return:
  - void
Location: /include/net/gro.h
parameter:
  - napi_struct
---
>`napi->rx_list`를 통째로 parameter로 넘기면서, `napi->rx_list`와 `napi->rx_count`를 초기화 하고 있다. 따라서, `netif_receive_skb_list_internal`에서 해당 리스트에 있는 skb들은 완전히 스택으로 넘어가서 처리되는 것으로 보인다.

[[김기수/산협 프로젝트 2/백서 제작용/netif_receive_skb_list_internal()]]