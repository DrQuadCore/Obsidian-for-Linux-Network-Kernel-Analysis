# Input-Output Memory Management Unit (IOMMU)
### MMU
**정의**
- CPU가 사용하는 virtual address를 physical address로 translate 해 주는 HW

**이점**
+ Address Translation Optimization
	+ TLB(Translation Lookaside Buffer)
+ Memory Protection

**동작**
1. cpu가 virtual address로 메모리 접근 시도
2. MMU가 TLB lookup  
   2-1. TLB Miss  
   → page table을 walk하여 VA → PA 매핑 search  
   → 해당 매핑 정보를 TLB에 새로 caching  
   → access 재시도  

   2-2. TLB Hit  
   → 매핑 정보를 바탕으로 flag bits 검사  
   → 접근이 가능하면 physical address 반환  
   → 접근이 불가능한 경우, Exception 발생

### IOMMU 
**정의**
- device가 사용하는 I/O virtual address(= IOVA) 를 physical address로 translate 해 주는 HW 

**기능**
**1. DMA Remapping** (핵심 기능)
+ PCI device는 CPU의 개입 없이 DMA로 메모리에 접근 가능 → 보안 문제
+ DMA remapping 기능을 통해 devices가 사용하는 주소(= I/O VA, IOVA)를 physical address로 안전하게 mapping 가능 → device별 접근 가능한 메모리 범위 제한 가능

**2. Interrupt Remapping** (확장 기능)
+ PCI device는 data를 다 처리하거나 event가 발생하면 interrupt를 보냄
+ 하나의 host에 여러 VM이 동시에 돌아가는 상황 혹은 멀티 CPU의 경우, interrupt를 전달 받을 대상을 정확히 결정해야 함
+ interrupt remapping table을 참조하여, 어느 vm/cpu에 interrupt를 전달할지 지정 
### IOMMU Subsystem in Linux Kernel
+ IOMMU DMA Layer 
	+ IOVA와 physical address의 mapping을 위한 정보 세팅, 이후 generic layer에게 요청 전달
+ IOMMU Generic Layer
	+ HW마다 다양한 IOMMU 동작 방식이 다르기 때문에 kernel이 직접 처리하면 너무 복잡해짐
	+ 어떠한 HW든 위에서 공통된 IOMMU 함수를 사용할 수 있도록 함
	+ IOMMU DMA Layer가 보낸 요청을 적절한 HW Driver에게 전달
- Hardware Specific IOMMU Layer
	- IOVA/PA mapping 정보를 실제 IOMMU HW가 사용할 수 있도록 page table 설정
		- page table은 domain 단위로 DRAM에 존재
		- domain: 같은 주소 변환 (IOVA→PA 매핑)을 공유하는 디바이스의 그룹

자료: [An Introduction to IOMMU Infrastructure in the Linux Kernel](https://lenovopress.lenovo.com/lp1467.pdf)

### IOMMU 기반 DMA 처리 흐름 - 초기 설정
1. device driver가 DMA 요청 (DMA 대상이 될 VA 버퍼(시작 주소 + 크기) 전체를 파라미터로 전달)
	- device가 접근 가능한 주소를 얻기 위함
2. DMA mapping layer에서 VA → PA 변환 수행
	- direct DMA가 가능한 상황인지 확인 (IOMMU가 비활성화/direct access 허용된 메모리 영역)
	- 가능하면 physical address 반환 
3. direct DMA가 불가능한 경우, DMA request를 IOMMU subsystem에 전달
4. IOMMU subsystem은 전달받은 PA에 대해 IOVA를 새로 할당
	- 전달받은 PA에 대해 device가 사용할 수 있는 주소, IOVA를 새로 할당
	- 해당 device가 속한 domain의 page table에 새로 할당한 IOVA와 PA mapping 정보 기록
	- IOVA 반환
		-  이후, device driver가 IOVA 범위를 device에 전달
		-  device가 IOVA로 DMA 수행
		- IOMMU HW가 IOVA → PA 변환해서 실제 메모리 접근

### IOMMU 기반 DMA 처리 흐름 - 수행 단계
1. driver로부터 설정된 IOVA 범위를 바탕으로, device가 DMA 요청 전송
2. IOMMU가 IOTLB(IOMMU 내부의 캐시) lookup  
   2.1. IOTLB Miss  
	→ page table을 walk하여 IOVA → PA 매핑 search  
	→ 해당 매핑 정보를 IOTLB에 새로 caching  
	  (해당 IOVA의 매핑이 존재하지 않는 경우, page fault처럼 OS가 개입하여 매핑을 생성하는 구조 아니라 IOMMU가 fault를 발생시키고 DMA 요청은 drop 되거나 시스템에 fault report를 남김)
	
   2.2. IOTLB Hit  
	→ 매핑 정보를 바탕으로 flag bits 검사  
	→ 접근이 가능하면 physical address 반환  
	→ 접근이 불가능한 경우,  Exception 발생  
	