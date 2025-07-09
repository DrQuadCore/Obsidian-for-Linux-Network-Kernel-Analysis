---
sticker: ""
---
1. 배경
    - 고속 네트워크 환경의 변화
        - 10Gbps 네트워크 환경에서는 64바이트 패킷 기준으로 초당 약 1,480만 개의  패킷 처리 요구한다.
    - 기존 시스템
        - NIC(Network Interface Card)는 DMA를 통해 데이터를 시스템 메모리에 복사하고,
        - CPU는 그 데이터를 다시 메모리에서 읽어오기 때문에 cache miss 발생률이 매우 높다.
        - 결과적으로 memory latency 및 bandwidth가 병목이 되어, 고속 네트워크 처리에 부적합하다.
2. DCA란?
    - I/O 장치(NIC 등)가 수신한 데이터를 시스템 메모리로 가지 않고, 곧바로 CPU 캐시(Cache)로 전송하는 기술
    - 기존 방식 vs DCA 방식의 캐시 상태 변화 (MESI 기준)
    
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
	System Interconnect + SCU(어느 캐시가 어느 주소에 대한 상태인지 등을 알고 어디로 보낼 지 결정, MESI 결정)
	  → Snoop broadcast
		  ↓
	L3 Cache (LLC, DDIO 영역)에 write

| 단계  | 기존 방식 (DMA 사용)                                      | DCA 방식                         |
| --- | --------------------------------------------------- | ------------------------------ |
| 1   | NIC가 메모리에 데이터 저장 -> 해당 주소의 캐시라인은 Invalid (I) 처리됨    | NIC가 데이터를 CPU Cache로 직접 씀      |
| 2   | CPU가 나중에 해당 데이터 읽을 때 → **Compulsory cache miss** 발생 | 데이터가 이미 Cache에 있음 → **Hit** 가능 |
| 3   | CPU가 캐시 miss 시 메모리 접근 → 대기 시간 큼                     | 메모리 접근 없이 Cache 바로 사용          |
| 4   | NIC는 항상 메모리 접근 → 불필요한 memory bandwidth 소비           | 메모리 접근이 줄어듦 → bandwidth 절약     |

	