---
Parameter:
  - ice_rx_ring
  - xdp_buff
  - bpf_prog
  - ice_tx_ring
  - ice_rx_buf
  - ice_32b_rx_flex_desc
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_run_xdp()
/**
 * ice_run_xdp - Executes an XDP program on initialized xdp_buff
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 * @xdp_prog: XDP program to run
 * @xdp_ring: ring to be used for XDP_TX action
 * @rx_buf: Rx buffer to store the XDP action
 * @eop_desc: Last descriptor in packet to read metadata from
 *
 * Returns any of ICE_XDP_{PASS, CONSUMED, TX, REDIR}
 */
static void
ice_run_xdp(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp,
	    struct bpf_prog *xdp_prog, struct ice_tx_ring *xdp_ring,
	    struct ice_rx_buf *rx_buf, union ice_32b_rx_flex_desc *eop_desc)
{
	unsigned int ret = ICE_XDP_PASS;
	u32 act;

	if (!xdp_prog)
		goto exit;

	ice_xdp_meta_set_desc(xdp, eop_desc);

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		if (static_branch_unlikely(&ice_xdp_locking_key))
			spin_lock(&xdp_ring->tx_lock);
		ret = __ice_xmit_xdp_ring(xdp, xdp_ring, false); // [[__ice_xmit_xdp_ring()]]
		if (static_branch_unlikely(&ice_xdp_locking_key))
			spin_unlock(&xdp_ring->tx_lock);
		if (ret == ICE_XDP_CONSUMED)
			goto out_failure;
		break;
	case XDP_REDIRECT:
		if (xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog))
			goto out_failure;
		ret = ICE_XDP_REDIR;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
out_failure:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		ret = ICE_XDP_CONSUMED;
	}
exit:
	ice_set_rx_bufs_act(xdp, rx_ring, ret);
}
```

[[__ice_xmit_xdp_ring()]]

> bpf_prog_run_xdp(xdp_prog, xdp) 함수를 를 통해서 act를 얻게 되고, 이걸 바탕으로 switch문으로 들어가게 된다. XDP_PASS, XDP_TX, XDP_REDIRECT, XDP_ABORTED, XDP_DROP 등의 enum이 있으며, 가운데 bpf_prog_run_xdp()를 통해 bpf가 실행되는데, 여기서 XDP_PASS act가 되어 ret이 ICE_XDP_PASS가 되면 네트워크 스택을 지나지 않는 것이고, 아니라면 XDP_DROP에서 ret이 ICE_XDP_CONSUMED로 전통적인 네트워크 스택을 지나게 될 것이다.