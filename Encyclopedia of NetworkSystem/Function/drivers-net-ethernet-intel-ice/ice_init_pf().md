---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
sticker: ""
---

```c title=ice_init_pf()
/**
 * ice_init_pf - Initialize general software structures (struct ice_pf)
 * @pf: board private structure to initialize
 */
static int ice_init_pf(struct ice_pf *pf)
{
	ice_set_pf_caps(pf);

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->tc_mutex);
	mutex_init(&pf->adev_mutex);
	mutex_init(&pf->lag_mutex);

	INIT_HLIST_HEAD(&pf->aq_wait_list);
	spin_lock_init(&pf->aq_wait_lock);
	init_waitqueue_head(&pf->aq_wait_queue);

	init_waitqueue_head(&pf->reset_wait_queue);

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, ice_service_timer, 0);
	pf->serv_tmr_period = HZ;
	INIT_WORK(&pf->serv_task, ice_service_task);
	clear_bit(ICE_SERVICE_SCHED, pf->state);

	mutex_init(&pf->avail_q_mutex);
	pf->avail_txqs = bitmap_zalloc(pf->max_pf_txqs, GFP_KERNEL);
	if (!pf->avail_txqs)
		return -ENOMEM;

	pf->avail_rxqs = bitmap_zalloc(pf->max_pf_rxqs, GFP_KERNEL);
	if (!pf->avail_rxqs) {
		bitmap_free(pf->avail_txqs);
		pf->avail_txqs = NULL;
		return -ENOMEM;
	}

	mutex_init(&pf->vfs.table_lock);
	hash_init(pf->vfs.table);
	ice_mbx_init_snapshot(&pf->hw);

	return 0;
}
```

