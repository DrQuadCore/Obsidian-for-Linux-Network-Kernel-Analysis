---
Parameter:
  - ice_rx_ring
  - ice_32b_rx_flex_desc
  - sk_buff
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx_lib.c
---

```c title=ice_process_skb_fields()
/**
 * ice_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: Rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
void
ice_process_skb_fields(struct ice_rx_ring *rx_ring,
		       union ice_32b_rx_flex_desc *rx_desc,
		       struct sk_buff *skb)
{
	u16 ptype = ice_get_ptype(rx_desc);

	ice_rx_hash_to_skb(rx_ring, rx_desc, skb, ptype);

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);

	ice_rx_csum(rx_ring, skb, rx_desc, ptype);

	if (rx_ring->ptp_rx)
		ice_ptp_rx_hwts_to_skb(rx_ring, rx_desc, skb);
}
```

> skb 필드를 처리하기 위해 사용되는 함수. ring, descriptor, packet informaion등의 정보를 체크하고, hash, checksum, VLAN, protocol 등의 필드를 채우게 된다.
