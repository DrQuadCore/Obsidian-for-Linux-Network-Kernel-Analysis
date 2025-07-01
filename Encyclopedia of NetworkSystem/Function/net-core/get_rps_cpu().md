---
Parameter:
  - net_device
  - sk_buff
  - rps_dev_flow
Return: int
Location: /net/core/dev.c
---

![[Pasted image 20240811235306.png]]
```c
static int get_rps_cpu(struct net_device *dev, struct sk_buff *skb,
		       struct rps_dev_flow **rflowp)
{
	const struct rps_sock_flow_table *sock_flow_table;
	struct netdev_rx_queue *rxqueue = dev->_rx;
	struct rps_dev_flow_table *flow_table;
	struct rps_map *map;
	int cpu = -1;
	u32 tcpu;
	u32 hash;

	if (skb_rx_queue_recorded(skb)) {
		u16 index = skb_get_rx_queue(skb);

		if (unlikely(index >= dev->real_num_rx_queues)) {
			WARN_ONCE(dev->real_num_rx_queues > 1,
				  "%s received packet on queue %u, but number "
				  "of RX queues is %u\n",
				  dev->name, index, dev->real_num_rx_queues);
			goto done;
		}
		rxqueue += index;
	}

	/* Avoid computing hash if RFS/RPS is not active for this rxqueue */

	flow_table = rcu_dereference(rxqueue->rps_flow_table);
	map = rcu_dereference(rxqueue->rps_map);
	if (!flow_table && !map)
		goto done;

	skb_reset_network_header(skb);
	hash = skb_get_hash(skb);
	if (!hash)
		goto done;

	sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
	if (flow_table && sock_flow_table) {
		struct rps_dev_flow *rflow;
		u32 next_cpu;
		u32 ident;

		/* First check into global flow table if there is a match.
		 * This READ_ONCE() pairs with WRITE_ONCE() from rps_record_sock_flow().
		 */
		ident = READ_ONCE(sock_flow_table->ents[hash & sock_flow_table->mask]);
		if ((ident ^ hash) & ~net_hotdata.rps_cpu_mask)
			goto try_rps;

		next_cpu = ident & net_hotdata.rps_cpu_mask;

		/* OK, now we know there is a match,
		 * we can look at the local (per receive queue) flow table
		 */
		rflow = &flow_table->flows[hash & flow_table->mask];
		tcpu = rflow->cpu;

		/*
		 * If the desired CPU (where last recvmsg was done) is
		 * different from current CPU (one in the rx-queue flow
		 * table entry), switch if one of the following holds:
		 *   - Current CPU is unset (>= nr_cpu_ids).
		 *   - Current CPU is offline.
		 *   - The current CPU's queue tail has advanced beyond the
		 *     last packet that was enqueued using this table entry.
		 *     This guarantees that all previous packets for the flow
		 *     have been dequeued, thus preserving in order delivery.
		 */
		if (unlikely(tcpu != next_cpu) &&
		    (tcpu >= nr_cpu_ids || !cpu_online(tcpu) ||
		     ((int)(per_cpu(softnet_data, tcpu).input_queue_head -
		      rflow->last_qtail)) >= 0)) {
			tcpu = next_cpu;
			rflow = set_rps_cpu(dev, skb, rflow, next_cpu);
		}

		if (tcpu < nr_cpu_ids && cpu_online(tcpu)) {
			*rflowp = rflow;
			cpu = tcpu;
			goto done;
		}
	}

try_rps:

	if (map) {
		tcpu = map->cpus[reciprocal_scale(hash, map->len)];
		if (cpu_online(tcpu)) {
			cpu = tcpu;
			goto done;
		}
	}

done:
	return cpu;
}
```

[[netdev_rx_queue]]
[[rps_map]]
[[rps_dev_flow_table]]

get_rps_cpu 함수는 `netif_receive_skb` 에서 호출된 함수로 네트워크 스택에서 패킷을 처리할 CPU를 결정하는 데 사용된다. 이 함수는 특정 네트워크 장치에서 수신된 패킷(skb)을 기반으로 가장 적합한 CPU를 선택한다.

``` c
static int get_rps_cpu(struct net_device *dev, struct sk_buff *skb,
                       struct rps_dev_flow **rflowp)
{
    const struct rps_sock_flow_table *sock_flow_table;
    struct netdev_rx_queue *rxqueue = dev->_rx;
    struct rps_dev_flow_table *flow_table;
    struct rps_map *map;
    int cpu = -1;
    u32 tcpu;
    u32 hash;
```
 
 함수는 네트워크 장치(dev)와 패킷(skb)을 기반으로 여러 데이터 구조를 초기화한다. cpu는 기본적으로 -1로 초기화되어 유효하지 않은 CPU를 의미한다. 이후 skb가 기록된 RX 큐를 사용해야 하는지 확인한다. RX 큐는 패킷이 수신된 큐를 나타내며, rxqueue 변수에 해당 큐를 참조한다.

``` c
    if (skb_rx_queue_recorded(skb)) {
        u16 index = skb_get_rx_queue(skb);

        if (unlikely(index >= dev->real_num_rx_queues)) {
            WARN_ONCE(dev->real_num_rx_queues > 1,
                      "%s received packet on queue %u, but number "
                      "of RX queues is %u\n",
                      dev->name, index, dev->real_num_rx_queues);
            goto done;
        }
        rxqueue += index;
    }
```

skb가 유효한 RX 큐에서 수신된 경우인지 검사한다. RX 큐의 인덱스가 올바른지 확인하고, 그렇지 않으면 경고를 출력하고 종료한다.

``` c
    flow_table = rcu_dereference(rxqueue->rps_flow_table);
    map = rcu_dereference(rxqueue->rps_map);
    if (!flow_table && !map)
        goto done;

    skb_reset_network_header(skb);
    hash = skb_get_hash(skb);
    if (!hash)
        goto done;
```

rps_flow_table과 rps_map이 설정되어 있는지 확인한다. 둘 다 설정되지 않았다면 RPS가 비활성화된 것으로 판단하고 종료한다. 이후 패킷의 해시 값을 계산한다. 해시 값은 RPS/RFS에서 패킷 흐름을 결정하는 데 사용된다.

``` c
    sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
    if (flow_table && sock_flow_table) {
        struct rps_dev_flow *rflow;
        u32 next_cpu;
        u32 ident;

        ident = READ_ONCE(sock_flow_table->ents[hash & sock_flow_table->mask]);
        if ((ident ^ hash) & ~net_hotdata.rps_cpu_mask)
            goto try_rps;

        next_cpu = ident & net_hotdata.rps_cpu_mask;

        rflow = &flow_table->flows[hash & flow_table->mask];
        tcpu = rflow->cpu;
```

sock_flow_table에서 현재 패킷의 해시 값과 일치하는 항목이 있는지 확인합니다. next_cpu에 일치하는 CPU를 저장한다. 로컬 흐름 테이블에서 패킷이 지정된 CPU와 일치하는지 확인한다. 만약 지정된 CPU가 다르거나 오프라인 상태이거나 큐에 더 이상 패킷이 없다면, CPU를 새로 설정한다.

``` c
        if (unlikely(tcpu != next_cpu) &&
            (tcpu >= nr_cpu_ids || !cpu_online(tcpu) ||
             ((int)(per_cpu(softnet_data, tcpu).input_queue_head -
              rflow->last_qtail)) >= 0)) {
            tcpu = next_cpu;
            rflow = set_rps_cpu(dev, skb, rflow, next_cpu);
        }

        if (tcpu < nr_cpu_ids && cpu_online(tcpu)) {
            *rflowp = rflow;
            cpu = tcpu;
            goto done;
        }
    }
```

CPU가 현재 유효하고 온라인 상태인지 확인한다. 만약 유효하다면, cpu 변수를 업데이트하고 종료한다.

``` c
try_rps:

    if (map) {
        tcpu = map->cpus[reciprocal_scale(hash, map->len)];
        if (cpu_online(tcpu)) {
            cpu = tcpu;
            goto done;
        }
    }

done:
    return cpu;
}
```

 만약 위에서 CPU를 찾지 못했을 경우, RPS 맵을 사용하여 CPU를 결정한다. map에서 계산된 tcpu가 온라인 상태라면 해당 CPU를 사용한다. 최종적으로 결정된 CPU 값을 반환합니다. 유효한 CPU를 찾지 못했을 경우, -1을 반환한다.