# Obsidian for Linux Network Kernel Analysis
Welcome to SKKU NetSys Lab Undergraduate Obsidian for Linux Network Kernel Analysis

> Linux 6.9를 기준으로 작성되었으며, NIC은 intel 100G NIC(aka ICE)를 사용한다고 가정하였습니다.

아래는 디렉토리 별 설명을 작성해두었습니다. 
## Encyclopedia of NetworkSystem
파일의 단위는 하나의 Function과 Struct를 기준으로 정리되어있습니다.

폴더의 이름이 해당 Function 혹은 Struct의 경로이며, 파일의 이름이 Function 혹은 Struct의 이름입니다.
Attributes에 Parameter, Return, Location이 정리되어 있으며, 해당 Function 혹은 Struct의 코드와 함께 간략한 설명이 작성되어 있습니다. 

파일 안에 주요 함수들의 링크도 연결되어 있으니, 참고하시기 바랍니다. 
## Excalidraw
### RPS-IPI 관계도

### sock
### 주요 개념 구조도
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