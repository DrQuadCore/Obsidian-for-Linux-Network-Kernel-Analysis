# DCA
---
> Direct Cache Access
- NIC이나 기타 고속 I/O 장치가 CPU의 메인 메모리가 아닌 CPU의 캐시에 직접 전송하도록 하는 기술이다.
- **작동 방식**
	1. NIC 등 I/O 장치가 패킷을 수신한다.
	2. DMA 엔진에서 TLP(Transaction Layer Packet)에 Steering Tag를 설정한다.
		- TLP : PCIe의 계층에서 데이터를 전달하는 단위이다.
		- Steering Tag : 해당 TLP가 어느 캐시에 대한 내용인지를 나타낸다.
	3. TLP를 CPU(칩셋)로 보내면 CPU의 Uncore 부분 중 DDIO모듈 (인텔)이 해당 TLP를 확인한다.
	4. DDIO가 TLP의 Steering Tag를 확인하고 데이터를 캐시나 메모리로 보낸다.
	5. 캐시로 보낸 경우, 코어에서 패킷 처리 후 필요시에만 DRAM에 기록한다.
- 관련 문제
	- DCA가 활성화된 경우, DRAM이 아닌 캐시에만 데이터가 쓰여진다.
	- 앞서 캐시에 저장되어있었지만 아직 처리가 안된 데이터가 새로운 데이터에 의해 덮어 씌워질 수 있다.
	- 이 때, 단순히 덮어 씌우는 것이 아닌 기존의 데이터는 캐시 플러시를 하여 DRAM으로 write-back한다.