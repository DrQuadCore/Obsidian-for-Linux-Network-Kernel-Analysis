# DCA
---
> Direct Cache Access
- NIC이나 기타 고속 I/O 장치가 CPU의 메인 메모리가 아닌 CPU의 캐시에 직접 전송하도록 하는 기술이다.
## 배경
- 10Gbps 네트워크 환경에서는 64바이트 패킷 기준으로 초당 약 1,480만 개의 패킷 처리를 요구한다.
	- 과거와 달리 처리해야할 패킷이 늘어났다.
- NIC은 DMA를 통해 데이터를 메모리에 복사하고 CPU는 그 데이터를 다시 메모리에서 읽어오기 때문에 캐시 미스 등 오버헤드가 매우 높다.
	- 캐시 미스로 인해 메모리 -> 캐시와 같은 데이터 복사
- 결과적으로 memory latency가 발생하여 기존의 방식은 고속 네트워크 환경에서 부적합하다.

## 기본 작동 방식(인텔 DDIO 기준)
1. NIC와 CPU가 PCIe로 연결되어있다.
2. NIC 등 I/O 장치가 패킷을 수신한다.
3. DMA 엔진에서 TLP(Transaction Layer Packet)에 Steering Tag를 설정한다.
	- TLP : PCIe의 계층에서 데이터를 전달하는 단위이다.
	- Steering Tag : 해당 TLP가 어느 캐시에 대한 내용인지를 나타낸다.
		- 데이터를 저장할 캐시 set, 캐시 way에 대한 정보를 나타낸다.
		- DMA 엔진은 실제 캐시 구조를 모르기 때문에 단지 특정 set과 way를 선호한다만 나타내는 것이며, 실제 캐시에서의 저장 위치는 다를 수 있다.
4. TLP를 CPU(칩셋)로 보내면 CPU의 Uncore 부분 중 PCIe Root Complex가 해당 TLP를 확인한다.
5. TLP의 Steering Tag를 확인하고 CPU의 메모리 컨트롤러나 LLC 컨트롤러를 통해 데이터를 캐시나 메모리에 저장한다.  
	- ST를 통해 판단은 PCIe Root Complex가 하고 실제적인 동작은 LLC 컨트롤러를 통해 진행한다.

## 상황별 작동 방식
- 보통 UMA는 단일 소켓 환경, NUMA는 멀티 소켓 환경이다.
	- 소켓 인터리빙을 이용한 멀티 소켓 UMA, 소켓 분할을 통한 단일 소켓 NUMA 환경이 있을 수 있으나, 일반적이지 않다.
- NUMA 환경에서 remote NUMA 노드로 DCA는 불가능하다.
### UMA / DMA
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
### UMA / DCA
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
### NUMA / DMA / Local node
- UMA / DMA 상황과 동일하다.
### NUMA / DCA / Local node
- NUMA / DCA 상황과 동일하다.
### NUMA / DMA / Remote node
1. NIC이 패킷을 수신한다.
2. DMA 엔진에서 TLP를 설정한다.
	1. DMA를 사용할 예정이므로 vm_st_valid 값을 0으로 설정한다.
	2. rx 디스크립터를 보고 TLP 헤더에 remote 노드의 address를 기록한다.
3. NIC과 PCIe 레인으로 연결된 CPU로 TLP를 전송한다.
4. CPU의 PCIe Root Complex가 TLP를 확인한다.
	1. address가 local 노드가 아니므로 remote 노드로 보내고자 한다.
5. CPU간 인터커넥트를 통해 local 노드에서 remote 노드로 메세지를 전송한다.
	1. 메세지 양식은 제조사별로 다르며, 비공개이다.
6. remote 노드의 CPU가 메세지를 받아 해당 CPU의 메모리 컨트롤러가 remote 메모리에 데이터를 적재한다.
7. DMA 엔진이 특정 코어에 IRQ를 발생시킨다.
8. 해당 코어가 NAPI를 통하여 패킷을 가져와 처리한다.

## 관련 문제
- DCA가 활성화된 경우, DRAM이 아닌 캐시에만 데이터가 쓰여진다.
- 앞서 캐시에 저장되어있었지만 아직 처리가 안된 데이터가 새로운 데이터에 의해 덮어 씌워질 수 있다.
- 이 때, 단순히 덮어 씌우는 것이 아닌 기존의 데이터는 캐시 플러시를 하여 DRAM으로 write-back한다.
- 추후, 해당 데이터를 읽기 위해선 다시 DRAM에서 캐시로 데이터를 복사해야 한다.
	- 오버헤드 발생!

## DMA 방식과 DCA 방식의 캐시 상태 변화
- MESI 프로토콜: CPU cache 일관성을 유지하기 위한 대표적인 프로토콜이다.
    - **M**odified: 캐시 데이터가 메모리보다 최신이고, 메모리에 쓰여지지 않은 상태이다.
    - **E**xclusive: 해당 캐시에서만 데이터를 소유하고 있으며, 메모리와 동일한 데이터이다.
    - **S**hared: 캐시와 메모리가 동일한 데이터이며, 다른 캐시에도 해당 캐시 데이터가 저장되어있다.
    - **I**nvalid: 캐시 내용이 유효하지 않으며 사용될 수 없다. 즉, 무효 상태이다.
- TLP 받은 후 내부 흐름
	PCIe TLP (non-coherent)
		  ↓
	PCIe Root Complex
	  →TLP Header 확인
	  → Interconnect Coherent 트랜잭션으로 변환
	     (예: Write-Invalidate or Write with Snoop)
		  ↓
	System Interconnect + SCU(어느 캐시의 어느 주소에 대한 MESI상태를 알고있어, 어디로 보낼 지 결정, MESI를 어떻게 변경할 지 결정)
	  → Targeted Snoop/Snoop broadcast

| 단계  | 기존 방식 (DMA 사용)                                                 | DCA 방식                                                                                                        |
| --- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1   | NIC에서 수신한 데이터는 PCIe Root Complex에서 DRAM Controller로 전송되어 저장된다. | NIC에서 수신한 데이터는  LLC로 전송되어 저장하며, 모든 캐시에 해당 주소의 캐시 라인을 Invalid 상태로 전이시킨다. (Write with Snoop)                    |
| 2   | 모든 캐시에서 해당 주소의 캐시 라인을 Invalid 상태로 전이시킨다.(Write-Invalidate)     | 타겟 LLC를 공유하는 CPU가 해당 주소에 접근 시, LLC에서 데이터를 읽고 자신의 캐시에 로드한다.                                                    |
| 3   | CPU가 해당 주소에 접근 시,  cache miss가 발생하고 DRAM에 접근하여 데이터를 읽어오게 된다.   | 타겟 LLC를 공유하지 않는 CPU가 해당 주소에 접근 시, 자신이 공유중인 LLC까지 miss가 발생하고 다른 LLC로 Snoop을 통해 탐색 후 Shared 상태로 변경하고 데이터를 가져온다. |



