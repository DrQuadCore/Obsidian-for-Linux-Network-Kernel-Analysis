---
Parameter:
  - ice_vsi
  - u16
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_base.c
---

```c title=ice_vsi_alloc_def()
/**
 * ice_vsi_alloc_q_vector - Allocate memory for a single interrupt vector
 * @vsi: the VSI being configured
 * @v_idx: index of the vector in the VSI struct
 *
 * We allocate one q_vector and set default value for ITR setting associated
 * with this q_vector. If allocation fails we return -ENOMEM.
 */
static int ice_vsi_alloc_q_vector(struct ice_vsi *vsi, u16 v_idx)
{
	struct ice_pf *pf = vsi->back;
	struct ice_q_vector *q_vector; // [[ice_q_vector]]
	int err;

	/* allocate q_vector */
	q_vector = kzalloc(sizeof(*q_vector), GFP_KERNEL); // [[kzalloc()]]
	if (!q_vector)
		return -ENOMEM;

	q_vector->vsi = vsi;
	q_vector->v_idx = v_idx;
	q_vector->tx.itr_setting = ICE_DFLT_TX_ITR;
	q_vector->rx.itr_setting = ICE_DFLT_RX_ITR;
	q_vector->tx.itr_mode = ITR_DYNAMIC;
	q_vector->rx.itr_mode = ITR_DYNAMIC;
	q_vector->tx.type = ICE_TX_CONTAINER;
	q_vector->rx.type = ICE_RX_CONTAINER;
	q_vector->irq.index = -ENOENT;

	if (vsi->type == ICE_VSI_VF) {
		q_vector->reg_idx = ice_calc_vf_reg_idx(vsi->vf, q_vector);
		goto out;
	} else if (vsi->type == ICE_VSI_CTRL && vsi->vf) {
		struct ice_vsi *ctrl_vsi = ice_get_vf_ctrl_vsi(pf, vsi);

		if (ctrl_vsi) {
			if (unlikely(!ctrl_vsi->q_vectors)) {
				err = -ENOENT;
				goto err_free_q_vector;
			}

			q_vector->irq = ctrl_vsi->q_vectors[0]->irq;
			goto skip_alloc;
		}
	}

	q_vector->irq = ice_alloc_irq(pf, vsi->irq_dyn_alloc); // [[ice_alloc_irq()]]
	if (q_vector->irq.index < 0) {
		err = -ENOMEM;
		goto err_free_q_vector;
	}

skip_alloc:
	q_vector->reg_idx = q_vector->irq.index;

	/* only set affinity_mask if the CPU is online */
	if (cpu_online(v_idx))
		cpumask_set_cpu(v_idx, &q_vector->affinity_mask);

	/* This will not be called in the driver load path because the netdev
	 * will not be created yet. All other cases with register the NAPI
	 * handler here (i.e. resume, reset/rebuild, etc.)
	 */
	if (vsi->netdev)
		netif_napi_add(vsi->netdev, &q_vector->napi, ice_napi_poll); // [[netif_napi_add()]] [[ice_napi_poll()]]
		//ice driver에서 사용하는 ice_napi_poll이라는 함수의 포인터를 전달하여 napi를 추가하는데 해당 함수포인터를 매핑하는 역할을 함. 
		//그런데 로드 될 때는 netdev가 없으므로 실행되지 않음. 따라서 앞에 if(vsi→netdev)가 붙게 됨.

out:
	/* tie q_vector and VSI together */
	vsi->q_vectors[v_idx] = q_vector;

	return 0;

err_free_q_vector:
	kfree(q_vector);

	return err;
}
```

[[ice_q_vector]]
[[kzalloc()]]
[[ice_alloc_irq()]]
[[netif_napi_add()]] 
[[ice_napi_poll()]]

1. ice_probe() → ice_init() → ice_vsi_init() → ice vsi alloc q vector()
2. q_vector을 위한 공간을 할당하는 함수이다
    a. q_vector 내부에 vsi, napi_struct, rx_queue, tx_queue 있다
    [[ice_q_vector]]
    ```c title=ice_q_vector
        struct ice_q_vector {
        	struct ice_vsi *vsi;
        
        	u16 v_idx;			/* index in the vsi-%3Eq_vector array. */
        	u16 reg_idx;
        	u8 num_ring_rx;			/* total number of Rx rings in vector */
        	u8 num_ring_tx;			/* total number of Tx rings in vector */
        	u8 wb_on_itr:1;			/* if true, WB on ITR is enabled */
        	/* in usecs, need to use ice_intrl_to_usecs_reg() before writing this
        	 * value to the device
        	 */
        	u8 intrl;
        
        	struct napi_struct napi;
        
        	struct ice_ring_container rx;
        	struct ice_ring_container tx;
        
        	cpumask_t affinity_mask;
        	struct irq_affinity_notify affinity_notify;
        
        	struct ice_channel *ch;
        
        	char name[ICE_INT_NAME_STR_LEN];
        
        	u16 total_events;	/* net_dim(): number of interrupts processed */
        	struct msi_map irq;
        } ____cacheline_internodealigned_in_smp;
 ```
        
3. 이미 vsi에 q_vector가 존재하면 넘어간다
4. q_vector = [[Encyclopedia of NetworkSystem/Function/include-linux/kzalloc().md|kzalloc]](sizeof(`*q_vector`), GFP_KERNEL)
    a. q_vector를 kzalloc()을 통해 공간 할당한다
    b. kzalloc() = kmalloc() + memset(), 연속된 공간 할당 + 0으로 초기화
    c. GFP_KERNEL : get free page, kernel data struct, inode cache, DMAable mem 에 사용
        i. GFP_NOWAIT (atomic context에서 allocation 할때 사용)
        ii. GFP_NOWARN (Allocations which have a reasonable fallback should be using)
        iii. GFP_ATOMIC….
5. vf일 경우 따로 처리를 해준다
    a. ice_alloc_irq 안함
6. q_vector->irq = [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_alloc_irq().md|ice_alloc_irq]](pf, vsi->irq_dyn_alloc)
    a. q_vector 마다 irq를 할당한다
    [[ice_alloc_irq()]]
    ```c title=ice_alloc_irq()
        /**
         * ice_alloc_irq - Allocate new interrupt vector
         * @pf: board private structure
         * @dyn_only: force dynamic allocation of the interrupt
         *
         * Allocate new interrupt vector for a given owner id.
         * return struct msi_map with interrupt details and track
         * allocated interrupt appropriately.
         *
         * This function reserves new irq entry from the irq_tracker.
         * if according to the tracker information all interrupts that
         * were allocated with ice_pci_alloc_irq_vectors are already used
         * and dynamically allocated interrupts are supported then new
         * interrupt will be allocated with pci_msix_alloc_irq_at.
         *
         * Some callers may only support dynamically allocated interrupts.
         * This is indicated with dyn_only flag.
         *
         * On failure, return map with negative .index. The caller
         * is expected to check returned map index.
         *
         */
        struct msi_map ice_alloc_irq(struct ice_pf *pf, bool dyn_only)
        {
        	int sriov_base_vector = pf->sriov_base_vector;
        	struct msi_map map = { .index = -ENOENT };
        	struct device *dev = ice_pf_to_dev(pf);
        	struct ice_irq_entry *entry;
        
        	**entry = ice_get_irq_res(pf, dyn_only);**
        	if (!entry)
        		return map;
        
        	/* fail if we're about to violate SRIOV vectors space */
        	if (sriov_base_vector && entry->index >= sriov_base_vector)
        		goto exit_free_res;
        
        	if (pci_msix_can_alloc_dyn(pf->pdev) && entry->dynamic) {
        		map = pci_msix_alloc_irq_at(pf->pdev, entry->index, NULL);
        		if (map.index %3C 0)
        			goto exit_free_res;
        		dev_dbg(dev, "allocated new irq at index %d\n", map.index);
        	} else {
        		map.index = entry->index;
        		map.virq = pci_irq_vector(pf->pdev, map.index);
        	}
        
        	return map;
        
        exit_free_res:
        	dev_err(dev, "Could not allocate irq at idx %d\n", entry->index);
        	ice_free_irq_res(pf, entry->index);
        	return map;
        }
```
        
    - msix (messeage signaled interrupt - x)
            - 권장되는 interrrupt 방식, 특히 multi rx queue NIC에서
            - 더 flexible 하다고 한다??
            - rx queue가 그것만의 hw interrupt를 할당할 수 있다. 이는 특정 cpu에 의해 관리된다?
            - This is because each RX queue can **have its own hardware interrupt assigned**, which can then be handled by a specific CPU (with `irqbalance` or by modifying `/proc/irq/IRQ_NUMBER/smp_affinity`) ???
    - interrupt vector 를 할당해준다
        - interrupt vector는 interrupt handler 으로의 주소가 적혀있다
        - Interrupt는 0에서 255까지 숫자와 연결되어 있고 interrupt vector와도 연결되어 있다.
        - interrupt vector을 모아 놓은게 interrupt vector table
        - interrupt이 발생할 경우, 이에 맞는 interrupt handler를 실행할 수 있다.
1. [[Encyclopedia of NetworkSystem/Function/include-linux/netif_napi_add().md|netif_napi_add]](vsi->netdev, &q_vector->napi, ice_napi_poll);
	a. netdevice가 존재할 경우 실행
	b. [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_napi_poll().md|ice_napi_poll()]] 을 polling function으로 사용
     i. tx queue 초기화, budget 분배, rx queue 초기화