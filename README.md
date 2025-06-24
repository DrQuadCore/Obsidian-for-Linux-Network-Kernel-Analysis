# Obsidian for Linux Network Kernel Analysis
Welcome to SKKU NetSys Lab Undergraduate Obsidian for Linux Network Kernel Analysis

	Linux 6.9를 기준으로 작성되었으며, NIC은 intel 100G NIC(aka ICE)를 사용한다고 가정하였습니다.
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
이 도식은 인터럽트부터 read syscall까지 receiver host kernel stack을 표시하고 있습니다. 

### 함수 콜 스택(TX)
Linux Stack 


## How to download kernel

https://mirrors.edge.kernel.org/pub/linux/kernel/

해당 링크에 들어가시면, 각 version에 따른 Linux Kernel 코드를 다운로드 받으실 수 있습니다. 저희 문서는 linux-6.9를 기준으로 작성되었으며, [linux-6.9.tar.xz](https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.9.tar.xz) 해당 링크를 통해 다운로드 받으실 수 있습니다. 