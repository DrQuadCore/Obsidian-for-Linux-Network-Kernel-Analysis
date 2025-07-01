---
Parameter:
  - net_device
Return: bool
Location: /include/linux/netdevice.h
---

```c title=netif_elide_gro()
static inline bool netif_elide_gro(const struct net_device *dev) // [[Encyclopedia of NetworkSystem/Struct/include-linux/net_device.md|net_device]]
{
	if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
		return true;
	return false;
}
```

[[Encyclopedia of NetworkSystem/Struct/include-linux/net_device.md|net_device]]

1. **GRO 기능 확인**:

- !(dev->features & NETIF_F_GRO): 네트워크 장치의 기능 비트마스크에서 GRO 기능이 활성화되지 않은 경우 true를 반환한다. 이는 dev->features 필드에서 NETIF_F_GRO 플래그를 확인하는 것이다.

2. **XDP 프로그램 확인**:

- dev->xdp_prog: 네트워크 장치에 XDP(eXpress Data Path) 프로그램이 설정되어 있는 경우 true를 반환한다. 이는 GRO를 사용할 수 없는 상태를 의미한다.

3. **결과 반환**:

- 위의 조건 중 하나라도 만족하면 true를 반환하여 GRO를 생략하도록 한다.
- 두 조건 모두 만족하지 않으면 false를 반환하여 GRO를 사용하도록 한다.