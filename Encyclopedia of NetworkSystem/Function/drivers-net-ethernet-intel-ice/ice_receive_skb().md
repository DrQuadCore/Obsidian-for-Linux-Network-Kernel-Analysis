---
Parameter:
  - ice_rx_ring
  - sk_buff
  - u16
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx_lib.c
---

```c title=ice_receive_skb()
/**
 * ice_receive_skb - Send a completed packet up the stack
 * @rx_ring: Rx ring in play
 * @skb: packet to send up
 * @vlan_tci: VLAN TCI for packet
 *
 * This function sends the completed packet (via. skb) up the stack using
 * gro receive functions (with/without VLAN tag)
 */
void
ice_receive_skb(struct ice_rx_ring *rx_ring, struct sk_buff *skb, u16 vlan_tci) // [[ice_rx_ring]] [[Encyclopedia of NetworkSystem/Struct/include-linux/sk_buff|sk_buff]]
{
	if ((vlan_tci & VLAN_VID_MASK) && rx_ring->vlan_proto)
		__vlan_hwaccel_put_tag(skb, rx_ring->vlan_proto,
				       vlan_tci);

	napi_gro_receive(&rx_ring->q_vector->napi, skb); // [[napi_gro_receive()]]
}
```

[[ice_rx_ring]]
[[Encyclopedia of NetworkSystem/Struct/include-linux/sk_buff|sk_buff]]
[[napi_gro_receive()]]

> 처리가 완료된 패킷을 스택으로 올려보내주는 역할을 하게 된다. napi_gro_receive() 호출하는 함수이다. gro가 가능하다면, gro 처리를 하여 skb를 만들게 된다.
