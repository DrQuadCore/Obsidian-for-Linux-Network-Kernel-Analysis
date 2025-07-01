---
Parameter:
  - ice_vsi
  - ice_channel
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_alloc_def()
static int
ice_vsi_alloc_def(struct ice_vsi *vsi, struct ice_channel *ch)
{
	if (vsi->type != ICE_VSI_CHNL) {
		ice_vsi_set_num_qs(vsi);
		if (ice_vsi_alloc_arrays(vsi))
			return -ENOMEM;
	}

	switch (vsi->type) {
	case ICE_VSI_SWITCHDEV_CTRL:
		/* Setup eswitch MSIX irq handler for VSI */
		vsi->irq_handler = ice_eswitch_msix_clean_rings;
		break;
	case ICE_VSI_PF:
		/* Setup default MSIX irq handler for VSI */
		vsi->irq_handler = ice_msix_clean_rings; // [[ice_msix_clean_rings()]]
		break;
	case ICE_VSI_CTRL:
		/* Setup ctrl VSI MSIX irq handler */
		vsi->irq_handler = ice_msix_clean_ctrl_vsi;
		break;
	case ICE_VSI_CHNL:
		if (!ch)
			return -EINVAL;

		vsi->num_rxq = ch->num_rxq;
		vsi->num_txq = ch->num_txq;
		vsi->next_base_q = ch->base_q;
		break;
	case ICE_VSI_VF:
	case ICE_VSI_LB:
		break;
	default:
		ice_vsi_free_arrays(vsi);
		return -EINVAL;
	}

	return 0;
}
```

[[ice_msix_clean_rings()]]

vsi의 타입에 따라 irq_handler가 정의되고 있는 함수임.

vsi의 종류에 따라 irq_handler가 다르게 allocation되고 있는것이 보임. 가장 기본적으로는 ice_msix_clean_rings() 라는 함수가 할당 되게 됨. irq_handler는 함수 포인터임. 이 함수는 같은 파일인 ice/ice_lib.c에 존재함.