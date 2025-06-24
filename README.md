# Obsidian for Linux Network Kernel Analysis
Welcome to SKKU NetSys Lab Undergraduate Obsidian for Linux Network Kernel Analysis (Authored by 김기수, 박찬서, 유지훈, 황재훈)

> Linux 6.9를 기준으로 작성되었으며, NIC은 intel 100G NIC(aka ICE)를 사용한다고 가정하였습니다.

아래는 디렉토리 별 설명을 작성해두었습니다. 
## Encyclopedia of NetworkSystem
파일의 단위는 하나의 Function과 Struct를 기준으로 작성되어있습니다.

폴더의 이름이 해당 Function 혹은 Struct의 경로이며, 파일의 이름이 Function 혹은 Struct의 이름입니다.
Attributes에 Parameter, Return, Location이 정리되어 있으며, 해당 Function 혹은 Struct의 코드와 함께 간략한 설명이 작성되어 있습니다. 

파일 안에 주요 함수들의 링크도 연결되어 있으니, 참고하시기 바랍니다. 
## Excalidraw
### RPS-IPI 관계도
우선 왼쪽위의 도식의 경우 패킷이 다른 core로 steering 되었을 때 어떻게 해당 코어에 인터럽트를 거는지 설명해주는 구조도 입니다. RPS, RFS등의 기법이 사용된 경우 Bottom half 중간에 enqueue_to_backlog를 통해 다른 코어로 steering이 될텐데, 이 때 해당코어가 이를 처리하기 위해 interrupt가 걸려야 할 것입니다. 따라서 inter-processor interrupt(IPI)가 사용되고, 이때 각 코어별로 maintain 중인 softnet_data(sd) 구조체를 참조하게 됩니다. 이 구조체는 커널 상에서 네트워크 관련 작업을 처리하기 위한 코어별로 할당된 구조체입니다.  

각 네모는 하나의 sd를 의미하고, 화살표는 해당 sd 구조체 내부에서 포인팅하는 field를 의미하고 있습니다. 구체적인 동작설명은 그림 내부를 참조하시면 됩니다.  그 오른쪽에는 softnet_data structure의 필드별 설명을 담고 있습니다. 여기서는 backlog queue를 처리하는 것과 코어별로 매핑된 점등등을 설명하고 있습니다.  
  
그 아래에는 어떻게 RPS/RFS가 이루어지고 있는지 설명합니다. RPS, RFS에 필요한 정보를 담고 있는 structure를 도식화 하였으며 각각 어떻게 동작하는지 간단한 도식도 추가하였습니다.  
  
가장 오른쪽에는 전체적인 추상화된 네트워크 스택입니다. 이는 RX 함수 콜 스택과 비교해서 보면 되겠습니다.  
### sock
따로 완성된 도식은 없으며 sock structure가 미완성인 형태로 남아있습니다. 그리고 오른쪽에는 L3 처리시에 사용되는 routing protocol에 대하여 간략하게 정리되어 있습니다.
### 주요 개념 구조도
여기서는 sk_buff의 대략적인 structure와, ring descriptor의 구조, 그리고 packet type structure에 대해서 설명하고 있습니다.  

ring descriptor의 경우 intel의 ICE driver를 기준으로 작성되었으며, 그 논리적인 구조를 도식화하였습니다.  

packet type의 경우 kernel의 interrupt context에서 L3 처리가 이루어지기 전 다루는 부분으로, 사용되는 부분은 `__netif_receive_skb_core` 함수 부분을 참고하면 됩니다.  

마지막으로 sk_buff 구조체의 경우 각 포인터들이 어떤 걸 가르키고 어떻게 사용되는지 대략적으로 정리되어 있습니다.  
### 함수 콜 스택(RX)
왼쪽 아래에 빨간 Start 부분이 인터럽트가 발생한 직후 커널이 시작되는 지점입니다.  

기본적으로 화살표를 따라서 함수가 실행된다고 보면 되고, 파란 직선으로 나뉜 것은 context별 구분입니다.  

각각의 네모 상자는 하나의 함수로, 실제 실행되는 함수 단위이며, 위치와 크기의 경우 가변적이나, perf의 flame graph와 동일한 의미를 지닌다고 간주하면 됩니다.  

각각의 함수들은 모두 Function 폴더에 정리되어 있으며,Ctrl + O를 통해 해당 함수 이름을 검색하여 해당 페이지를 방문하면 해당 함수의 상세한 설명을 확인할 수 있습니다.
### 함수 콜 스택(TX)
주요 TX syscall인 send(), sendto(), sendmsg()부터 ice driver 코드까지의 콜 스택을 Excalidraw plugin을 활용해 그려놓았습니다. 

기본적으로 RX 파트에 비해 훨씬 함수가 적은 것도 사실이지만, RX 이후에 남는 시간을 활용하여 그린만큼 빠진 부분이나 미흡한 부분들이 있을 가능성이 높습니다. 이 점 참고하여 부족한 부분들은 보충해나가시며 보시면 될 것 같습니다. 
## cf. How to Download Linux Kernel

https://mirrors.edge.kernel.org/pub/linux/kernel/

해당 링크에 들어가시면, 각 version에 따른 Linux Kernel 코드를 다운로드 받으실 수 있습니다. 저희 문서는 linux-6.9를 기준으로 작성되었으며, [linux-6.9.tar.xz](https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.9.tar.xz) 해당 링크를 통해 다운로드 받으실 수 있습니다. 