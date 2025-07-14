# DCA
---
> Direct Cache Access
- NIC이나 기타 고속 I/O 장치가 CPU의 메인 메모리가 아닌 CPU의 캐시에 직접 전송하도록 하는 기술이다.
- **작동 방식**
	1. NIC 등 I/O 장치가 패킷을 수신한다.
	2. DMA 엔진에서 TLP(Transaction Layer Packet)에 Steering Tag를 설정한다.
		- TLP : PCIe의 계층에서 데이터를 전달하는 단위이다.
		- Steering Tag : 해당 TLP가 어느 캐시에 대한 내용인지를 나타낸다.
			- 내부적으로 st_info라는 구조체를 사용한다.
				- vm_st_valid : 해당 ST가 유효한지를 나타낸다.
				- vm_st : 해당 ST 및 TLP가 어느 CPU의 어느 캐시 set의 캐시 way에 적용될 것인를 나타낸다.
	3. TLP를 CPU(칩셋)로 보내면 CPU의 Uncore 부분 중 DDIO모듈 (인텔)이 해당 TLP를 확인한다.
	4. DDIO가 TLP의 Steering Tag를 확인하고 데이터를 캐시나 메모리로 보낸다.
	5. 캐시로 보낸 경우, 코어에서 패킷 처리 후 필요시에만 DRAM에 기록한다.
- 관련 문제
	- DCA가 활성화된 경우, DRAM이 아닌 캐시에만 데이터가 쓰여진다.
	- 앞서 캐시에 저장되어있었지만 아직 처리가 안된 데이터가 새로운 데이터에 의해 덮어 씌워질 수 있다.
	- 이 때, 단순히 덮어 씌우는 것이 아닌 기존의 데이터는 캐시 플러시를 하여 DRAM으로 write-back한다.
- 상황별 작동 방식
	- 보통 UMA는 단일 소켓 환경, NUMA는 멀티 소켓 환경이다.
		- 소켓 인터리빙을 이용한 멀티 소켓 UMA, 소켓 분할을 통한 단일 소켓 NUMA 환경이 있을 수 있으나, 일반적이지 않다.
	- UMA / DMA 
		1. NIC이 패킷을 수신한다.
		2. DMA 엔진에서 TLP를 설정한다.
			1. DMA를 사용할 예정이므로 vm_st_valid 값을 0으로 설정한다.
			2. rx 디스크립터를 보고 데이터가 저장될 address를 확인한다.
			3. TLP 헤더에 해당 address를 기록한다.
		3. NIC과 PCIe 레인으로 연결된 CPU(칩셋)로 TLP를 전송한다.
		4. CPU의 PCIe Root Complex가 TLP를 확인한다.
		5. 메모리 컨트롤러를 통해 address가 가리키고 있는 메모리에 데이터를 적재한다.
		6. 메모리에 데이터가 올라갔으면 DMA 엔진이 특정 코어에 IRQ를 발생시킨다.
			1. aRFS 등으로 패킷을 직접적으로 처리할 코어이다.
		7. 해당 코어가 NAPI를 통하여 패킷을 가져와 처리한다.
	- UMA / DCA
		1. NIC이 패킷을 수신한다.
		2. DMA 엔진에서 TLP 및 ST를 설정한다.
			1. DCA를 사용할 예정이므로 vm_st_valid 값을 1로 설정한다.
			2. vm_st에 소켓 번호, 캐시 set, 캐시 way 정보를 설정한다.
			3. rx 디스크립터를 보고 TLP 헤더에 address를 기록한다.
		3. NIC과 PCIe 레인으로 연결된 CPU로 TLP를 전송한다.
		4. CPU의 PCIe Root Complex과 TLP와 ST를 확인한다.
		5. LLC 컨트롤러의 DDIO 모듈이 ST를 보고 캐시에 해당 데이터를 적재한다.
		6. 캐시에 데이터가 올라갔으면 DMA 엔진이 특정 코어에 IRQ를 발생시킨다.
		7. 해당 코어가 NAPI를 통하여 패킷을 가져와 처리한다.
	- NUMA / DMA / Local
		- UMA / DMA 상황과 동일하다.
	- NUMA / DCA / Local
		- UMA / DCA 상황과 동일하다.
	- NUMA / DMA / Remote
		1. NIC이 패킷을 수신한다.
		2. DMA 엔진에서 TLP를 설정한다.
			1. DMA를 사용할 예정이므로 vm_st_valid 값을 0으로 설정한다.
			2. rx 디스크립터를 보고 TLP 헤더에 remote 노드의 address를 기록한다.
		3. NIC과 PCIe 레인으로 연결된 CPU로 TLP를 전송한다.
		4. CPU의 PCIe Root Complex가 TLP를 확인한다.
			1. address가 local 노드가 아니므로 remote 노드로 보내고자 한다.
		5. CPU간 인터커넥트를 통해 local 노드에서 remote 노드로 메세지를 전송한다.
			1. 메세지 양식은 제조사별로 다르며, 비공개이다.
		6. remote 노드의 CPU가 메세지를 받아 해당 CPU의 메모리 컨트롤러가 remote 메모리에 데터를 적재한다.
		7. DMA 엔진이 특정 코어에 IRQ를 발생시킨다.
		8. 해당 코어가 NAPI를 통하여 패킷을 가져와 처리한다.