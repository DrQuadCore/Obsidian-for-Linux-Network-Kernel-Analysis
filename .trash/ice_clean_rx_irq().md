---
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
parameter:
  - ice_rx_ring
  - int
Return:
  - int
---
#### 설명
>xdp를 무조건 셋팅하는 것으로 보인다. 우선 없다고 가정하고 보면 if(!xdp→data)를 통해 확인하여 ice_add_xdp_frag() 함수를 실행할 것이다. 그러고 나서 ice_run_xdp()를 실행한다. 이후에 보면 construct_skb:라는 label이 존재한다. 이는 네트워크 스택에 링버퍼의 내용을 전달하는 뜻으로, ICE_XDP_PASS값을 rx_buf→act에서 가질 때 실행되게 된다. 그게 아니라면 중간의 continue; 때문에 construct_skb: 라벨 아래의 코드들은 실행되지 않게 된다. construct_skb: 라벨 아래에서는 전통적인 네트워크 스택이 진행되게 된다.
>
>중간에 ICE_RX_DESC() 매크로를 통하여 rx_ring의 ntc 인덱스에 있는 desc를 해당하는 구조체 타입으로 캐스팅하여 가져오게 된다.
>
>또한 만약 xdp->data가 null값이라면, 즉 xdp가 가르키고 있는 data 영역이 존재하지 않는다면, 직접 rx_buf-> page로 접근하여 해당 page_address를 hard_start로 하여 data 영역의 head 부분을 가르키게 한다. 이후 xdp_prepare_buff 함수를 호출하여 xdp_buff를 사용할 수 있도록 설정한다.
>
>budget을 다 사용하였을 경우 while문을 빠져나오게 되는데, 여기는 gro를 통해 전부 끝났을 경우이다.