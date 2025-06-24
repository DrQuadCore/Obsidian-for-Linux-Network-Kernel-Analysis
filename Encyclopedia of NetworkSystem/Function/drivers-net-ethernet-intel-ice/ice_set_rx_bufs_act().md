---
Parameter:
  - xdp_buff
  - ice_rx_ring
  - unsigned int
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx_lib.h
---

```c title=ice_set_rx_bufs_act()
/**
* ice_set_rx_bufs_act - propagate Rx buffer action to frags
* @xdp: XDP buffer representing frame (linear and frags part)
* @rx_ring: Rx ring struct
* act: action to store onto Rx buffers related to XDP buffer parts
*
* Set action that should be taken before putting Rx buffer from first frag
* to the last.
*/
static inline void
ice_set_rx_bufs_act(struct xdp_buff *xdp, const struct ice_rx_ring *rx_ring,
			const unsigned int act)
{
	u32 sinfo_frags = xdp_get_shared_info_from_buff(xdp)->nr_frags;
	u32 nr_frags = rx_ring->nr_frags + 1;
	u32 idx = rx_ring->first_desc;
	u32 cnt = rx_ring->count;
	struct ice_rx_buf *buf;
	  
	for (int i = 0; i < nr_frags; i++) {
		buf = &rx_ring->rx_buf[idx];
		buf->act = act;
		  
		if (++idx == cnt)
			idx = 0;
}

	/* adjust pagecnt_bias on frags freed by XDP prog */
	if (sinfo_frags < rx_ring->nr_frags && act == ICE_XDP_CONSUMED) {
		u32 delta = rx_ring->nr_frags - sinfo_frags;
		  
		while (delta) {
			if (idx == 0)
				idx = cnt - 1;
			else
				idx--;
			buf = &rx_ring->rx_buf[idx];
			buf->pagecnt_bias--;
			delta--;
		}
	}
}
```

>해당하는 패킷에 대하여 rx_buf 에 해당하는 xdp의 반환 값을 저장해주는 함수이다. xdp_get_shared_info_from_buff() 함수의 경우 xdp가 가르키고 있는 data 영역의 맨 마지막을 리턴하게 되는데, 이 함수는 include/net/xdp.h에 있다. data 영역의 시작 부분과 frame size를 통해 마지막에 달라 붙어 있는 skb_shared_info를 가르키는 포인터를 반환 할 수 밖에 없을 것이다.
>frag의 갯수만큼 for문을 돌려서 rx_buf array 중 idx로 해당하는 rx_buf에 접근하여 그 buf의 act를 인수로 받은 act로 설정하게 된다.
>
>추가적으로 만약 XDP program에 의해 freed 된 frags가 있다면 이를 반영하기 위해 pagecnt_bias를 조정해주는 코드도 있다. 이는 해당 링 버퍼에서 pagecnt_bias를 그 차이만큼 줄여주는 역할을 한다.

>first_desc는 링 구조에서 첫 번째 디스크립터의 인덱스 번호를 가르키고 있고, rx_ring의 nr_frags는 가지고 있는 유효한 디스크립터의 갯수를 의미한다. 또한, count는 전체(최대) 가질 수 있는 링 디스크립터의 수로, 여기서는 rx_buf array의 선언된 entry 최대 갯수라고 볼 수 있다.

