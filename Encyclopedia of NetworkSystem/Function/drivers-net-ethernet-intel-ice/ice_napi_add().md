---
Parameter:
  - ice_vsi
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_napi_add()
static void ice_napi_add(struct ice_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, v_idx) {
		netif_napi_add(vsi->netdev, &vsi->q_vectors[v_idx]->napi,
			       ice_napi_poll); // [[netif_napi_add()]]
		__ice_q_vector_set_napi_queues(vsi->q_vectors[v_idx], false); // _[[__ice_q_vector_set_napi_queues()]]
	}
}
```

[[netif_napi_add()]]
[[__ice_q_vector_set_napi_queues()]]
