---
Parameter:
  - ice_vsi
  - char
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_req_irq_msix()
/**
 * ice_vsi_req_irq_msix - get MSI-X vectors from the OS for the VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 */
static int ice_vsi_req_irq_msix(struct ice_vsi *vsi, char *basename)
{
	int q_vectors = vsi->num_q_vectors;
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	int rx_int_idx = 0;
	int tx_int_idx = 0;
	int vector, err;
	int irq_num;

	dev = ice_pf_to_dev(pf);
	for (vector = 0; vector < q_vectors; vector++) {
		struct ice_q_vector *q_vector = vsi->q_vectors[vector];

		irq_num = q_vector->irq.virq;

		if (q_vector->tx.tx_ring && q_vector->rx.rx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "TxRx", rx_int_idx++);
			tx_int_idx++;
		} else if (q_vector->rx.rx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "rx", rx_int_idx++);
		} else if (q_vector->tx.tx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "tx", tx_int_idx++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		if (vsi->type == ICE_VSI_CTRL && vsi->vf)
			err = devm_request_irq(dev, irq_num, vsi->irq_handler,
					       IRQF_SHARED, q_vector->name,
					       q_vector); // [[devm_request_irq()]]
		else
			err = devm_request_irq(dev, irq_num, vsi->irq_handler,
					       0, q_vector->name, q_vector); // [[devm_request_irq()]]
		if (err) {
			netdev_err(vsi->netdev, "MSIX request_irq failed, error: %d\n",
				   err);
			goto free_q_irqs;
		}

		/* register for affinity change notifications */
		if (!IS_ENABLED(CONFIG_RFS_ACCEL)) {
			struct irq_affinity_notify *affinity_notify;

			affinity_notify = &q_vector->affinity_notify;
			affinity_notify->notify = ice_irq_affinity_notify;
			affinity_notify->release = ice_irq_affinity_release;
			irq_set_affinity_notifier(irq_num, affinity_notify);
		}

		/* assign the mask for this irq */
		irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);
	}

	err = ice_set_cpu_rx_rmap(vsi); // [[ice_set_cpu_rx_rmap()]]
	if (err) {
		netdev_err(vsi->netdev, "Failed to setup CPU RMAP on VSI %u: %pe\n",
			   vsi->vsi_num, ERR_PTR(err));
		goto free_q_irqs;
	}

	vsi->irqs_ready = true;
	return 0;

free_q_irqs:
	while (vector--) {
		irq_num = vsi->q_vectors[vector]->irq.virq;
		if (!IS_ENABLED(CONFIG_RFS_ACCEL))
			irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, &vsi->q_vectors[vector]);
	}
	return err;
}
```

[[devm_request_irq()]]
[[ice_set_cpu_rx_rmap()]]

**msi-x?**

각각의 Rx queue는 구분되고 연관된 IRQ를 가지고 있다. NIC가 이걸 trigger하여 CPU가 새로운 패킷이 들어왔음을 알린다. PCIe를 통해 인터럽트를 일으키는 것으로 MSI-x를 사용하는데, 흔히 ifconfig를 했을 때 나오는 eth(x) 이 것을 가리킨다. 하드웨어 핀으로 인터럽트를 발생시키는 것은 장치 갯수에 한계가 있어 이를 메시지 형태로 발생시키게 하여 더 많은 장치를 다룰 수 있도록 하는 것이다. 이를 이용하여 NIC는 특정 CPU를 지정하여 처리하도록 보낼 수가 있다. 각각의 큐와 IRQ에 대한 매핑은 /proc/interrupt 에서 설정이 가능하다.