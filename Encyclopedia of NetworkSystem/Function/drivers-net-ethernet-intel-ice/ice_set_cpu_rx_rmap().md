---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_arfs.c
---

```c title=ice_set_cpu_rx_rmap()
/**
 * ice_set_cpu_rx_rmap - setup CPU reverse map for each queue
 * @vsi: the VSI to be forwarded to
 */
int ice_set_cpu_rx_rmap(struct ice_vsi *vsi)
{
	struct net_device *netdev;
	struct ice_pf *pf;
	int i;

	if (!vsi || vsi->type != ICE_VSI_PF)
		return 0;

	pf = vsi->back;
	netdev = vsi->netdev;
	if (!pf || !netdev || !vsi->num_q_vectors)
		return -EINVAL;

	netdev_dbg(netdev, "Setup CPU RMAP: vsi type 0x%x, ifname %s, q_vectors %d\n",
		   vsi->type, netdev->name, vsi->num_q_vectors);

	netdev->rx_cpu_rmap = alloc_irq_cpu_rmap(vsi->num_q_vectors);
	if (unlikely(!netdev->rx_cpu_rmap))
		return -EINVAL;

	ice_for_each_q_vector(vsi, i)
		if (irq_cpu_rmap_add(netdev->rx_cpu_rmap,
				     vsi->q_vectors[i]->irq.virq)) {
			ice_free_cpu_rx_rmap(vsi);
			return -EINVAL;
		}

	return 0;
}
```

각각의 queue에 대하여 aRFS를 위해 매핑하는 함수.