---
Parameter:
  - napi_struct
  - int
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_napi_poll()
/**
 * ice_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 */
int ice_napi_poll(struct napi_struct *napi, int budget)
{
	struct ice_q_vector *q_vector = // [[ice_q_vector]]
				container_of(napi, struct ice_q_vector, napi);
	struct ice_tx_ring *tx_ring; // [[ice_tx_ring]]
	struct ice_rx_ring *rx_ring; // [[ice_rx_ring]]
	bool clean_complete = true;
	int budget_per_ring;
	int work_done = 0;

	/* Since the actual Tx work is minimal, we can give the Tx a larger
	 * budget and be more aggressive about cleaning up the Tx descriptors.
	 */
	ice_for_each_tx_ring(tx_ring, q_vector->tx) {
		bool wd;

		if (tx_ring->xsk_pool)
			wd = ice_xmit_zc(tx_ring); // [[ice_xmit_zc()]]
		else if (ice_ring_is_xdp(tx_ring))
			wd = true;
		else
			wd = ice_clean_tx_irq(tx_ring, budget); // [[ice_clean_tx_irq()]]

		if (!wd)
			clean_complete = false;
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(budget <= 0))
		return budget;

	/* normally we have 1 Rx ring per q_vector */
	if (unlikely(q_vector->num_ring_rx > 1))
		/* We attempt to distribute budget to each Rx queue fairly, but
		 * don't allow the budget to go below 1 because that would exit
		 * polling early.
		 */
		budget_per_ring = max_t(int, budget / q_vector->num_ring_rx, 1);
	else
		/* Max of 1 Rx ring in this q_vector so give it the budget */
		budget_per_ring = budget;

	ice_for_each_rx_ring(rx_ring, q_vector->rx) {
		int cleaned;

		/* A dedicated path for zero-copy allows making a single
		 * comparison in the irq context instead of many inside the
		 * ice_clean_rx_irq function and makes the codebase cleaner.
		 */
		cleaned = rx_ring->xsk_pool ?
			  ice_clean_rx_irq_zc(rx_ring, budget_per_ring) :
			  ice_clean_rx_irq(rx_ring, budget_per_ring); // [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_clean_rx_irq()|ice_clean_rx_irq()]]
		work_done += cleaned;
		/* if we clean as many as budgeted, we must not be done */
		if (cleaned >= budget_per_ring)
			clean_complete = false;
	}

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		/* Set the writeback on ITR so partial completions of
		 * cache-lines will still continue even if we're polling.
		 */
		ice_set_wb_on_itr(q_vector);
		return budget;
	}

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (napi_complete_done(napi, work_done)) {
		ice_net_dim(q_vector); // [[ice_net_dim()]]
		ice_enable_interrupt(q_vector); // [[ice_enable_interrupt()]]
	} else {
		ice_set_wb_on_itr(q_vector);
	}

	return min_t(int, work_done, budget - 1);
}

```

[[ice_q_vector]]
[[ice_tx_ring]]
[[ice_rx_ring]]
[[ice_xmit_zc()]]
[[ice_clean_tx_irq()]]
[[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_clean_rx_irq()|ice_clean_rx_irq()]]
[[ice_net_dim()]]
[[ice_enable_interrupt()]]

> napi_poll은 Rx와 Tx를 동시에 다루게 된다. 모든 tx링에 대하여 ice_xmit_zc()혹은 ice_clean_tx_irq()등의 함수로 다루게 되는데 일단 bottom up path이므로 추후에 살펴보고자 한다. 각각의 rx_ring에 대하여 xsk_pool이 있다면 zc옵션이 있는 함수인 ice_clean_rx_irq_zc, 아니라면 ice_clean_rx_irq를 실행하게 된다.

특히 num_ring_rx를 확인하는 부분에서, 보통은 rx_ring이 1개임을 알 수 있다. unlikely로 if문에 들어가 있기 때문이다. 또한 이러한 경우, 각각의 rx_ring에 budget을 골고루 분배해야하기 때문에 budget_per_ring이 budget을 rx_ring의 갯수로 나눠준 값이 된다.

1. TX ring 초기화하기 (clean)
    1. wd = [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_xmit_zc().md|ice_xmit_zc]](tx_ring);
        1. xsk_pool 이 있을 경우, zero copy pkt tx 할 경우, kernel bypass에 사용된다?
        2. wd에 tx가 성공적이었는지 저장
    2. [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_ring_is_xdp().md|ice_ring_is_xdp]](tx_ring) 일 때는 항상 true로 설정한다
        1. xdp (express data path) 사용할 때
    3. wd = [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_clean_tx_irq().md|ice_clean_tx_irq]](tx_ring, budget);
        1. default tx 초기 과정이다
        2. descriptor를 free해준다
2. budget_per_ring = max_t(int, budget / q_vector->num_ring_rx, 1);
    1. budget은 rx_ring 개수로 나눠서 공평하게 배분한다
    2. 최소 1 은 받게 설정
3. clean rx ring
    1. clean 된 irq의 개수를 budget과 비교한다
    2. 만약 전자가 더 많으면 uncomplete된 상태이므로 계속 polling을 한다
    3. clean 된 개수와 budget을 대소 비교로 complete 여부를 알수있나?
4. if not complete, return the budget
5. exit polling
   [[ice_net_dim()]]
```c title=ice_net_dim()
/**
 * ice_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void ice_net_dim(struct ice_q_vector *q_vector)
{
	struct ice_ring_container *tx = &q_vector->tx;
	struct ice_ring_container *rx = &q_vector->rx;

	if (ITR_IS_DYNAMIC(tx)) {
		struct dim_sample dim_sample;

		__ice_update_sample(q_vector, tx, &dim_sample, true);
		net_dim(&tx->dim, dim_sample);
	}

	if (ITR_IS_DYNAMIC(rx)) {
		struct dim_sample dim_sample;

		__ice_update_sample(q_vector, rx, &dim_sample, false);
		net_dim(&rx->dim, dim_sample);
	}
}
```
	[[ice_enable_interrupt()]]
```c title=ice_enable_interrupt()
/**
 * ice_enable_interrupt - re-enable MSI-X interrupt
 * @q_vector: the vector associated with the interrupt to enable
 *
 * If the VSI is down, the interrupt will not be re-enabled. Also,
 * when enabling the interrupt always reset the wb_on_itr to false
 * and trigger a software interrupt to clean out internal state.
 */
static void ice_enable_interrupt(struct ice_q_vector *q_vector)
{
	struct ice_vsi *vsi = q_vector->vsi;
	bool wb_en = q_vector->wb_on_itr;
	u32 itr_val;

	if (test_bit(ICE_DOWN, vsi->state))
		return;

	/* trigger an ITR delayed software interrupt when exiting busy poll, to
	 * make sure to catch any pending cleanups that might have been missed
	 * due to interrupt state transition. If busy poll or poll isn't
	 * enabled, then don't update ITR, and just enable the interrupt.
	 */
	if (!wb_en) {
		itr_val = ice_buildreg_itr(ICE_ITR_NONE, 0);
	} else {
		q_vector->wb_on_itr = false;

		/* do two things here with a single write. Set up the third ITR
		 * index to be used for software interrupt moderation, and then
		 * trigger a software interrupt with a rate limit of 20K on
		 * software interrupts, this will help avoid high interrupt
		 * loads due to frequently polling and exiting polling.
		 */
		itr_val = ice_buildreg_itr(ICE_IDX_ITR2, ICE_ITR_20K);
		itr_val |= GLINT_DYN_CTL_SWINT_TRIG_M |
			   ICE_IDX_ITR2 << GLINT_DYN_CTL_SW_ITR_INDX_S |
			   GLINT_DYN_CTL_SW_ITR_INDX_ENA_M;
	}
	wr32(&vsi->back->hw, GLINT_DYN_CTL(q_vector->reg_idx), itr_val);
}
```

















