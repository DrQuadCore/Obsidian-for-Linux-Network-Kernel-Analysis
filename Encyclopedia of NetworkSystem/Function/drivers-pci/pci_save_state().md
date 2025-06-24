---
Parameter:
  - pci_dev
Return: int
Location: /drivers/pci/pci.c
---

```c title=pci_save_state()
/**
 * pci_save_state - save the PCI configuration space of a device before
 *		    suspending
 * @dev: PCI device that we're dealing with
 */
int pci_save_state(struct pci_dev *dev)
{
	int i;
	/* XXX: 100% dword access ok here? */
	for (i = 0; i < 16; i++) {
		pci_read_config_dword(dev, i * 4, &dev->saved_config_space[i]);
		pci_dbg(dev, "save config %#04x: %#010x\n",
			i * 4, dev->saved_config_space[i]);
	}
	dev->state_saved = true;

	i = pci_save_pcie_state(dev);
	if (i != 0)
		return i;

	i = pci_save_pcix_state(dev);
	if (i != 0)
		return i;

	pci_save_ltr_state(dev);
	pci_save_dpc_state(dev);
	pci_save_aer_state(dev);
	pci_save_ptm_state(dev);
	return pci_save_vc_state(dev);
}
EXPORT_SYMBOL(pci_save_state);
```

pci_save_state 함수는 PCI 장치의 현재 상태를 저장하는 역할을 한다. 이 함수는 PCI 구성 공간(Config Space)을 읽어와 저장하고, 다양한 PCIe 확장 상태를 저장한다. 이는 주로 시스템이 절전 모드로 전환되거나, 장치를 재설정할 때 현재 상태를 나중에 복원하기 위해 사용된다.
# 함수 설명

## **0. 함수 선언 및 변수 선언**

```c
int pci_save_state(struct pci_dev *dev)
{
	int i;
```

## 1. **PCI 구성 공간 저장**

```c
for (i = 0; i < 16; i++) {
    pci_read_config_dword(dev, i * 4, &dev->saved_config_space[i]);
    pci_dbg(dev, "save config %#04x: %#010x\\n",
        i * 4, dev->saved_config_space[i]);
}
dev->state_saved = true;
```

**목적**: PCI 구성 공간의 첫 16개 DWORD(64바이트)를 저장한다.

**설명**:

- for (i = 0; i < 16; i++): 구성 공간의 첫 16개 DWORD(64바이트)를 순회한다.
- pci_read_config_dword(dev, i * 4, &dev->saved_config_space[i]): pci_read_config_dword 함수를 사용해 구성 공간의 각 DWORD를 읽어 dev->saved_config_space 배열에 저장한다.
- pci_dbg(dev, "save config %#04x: %#010x\n", i * 4, dev->saved_config_space[i]): 디버그 로그를 출력하여 저장된 값을 확인한다.
- dev->state_saved = true: 상태가 저장되었음을 표시한다.

## 2. **PCIe 확장 상태 저장**

```c
i = pci_save_pcie_state(dev);
if (i != 0)
    return i;

i = pci_save_pcix_state(dev);
if (i != 0)
    return i;

pci_save_ltr_state(dev);
pci_save_dpc_state(dev);
pci_save_aer_state(dev);
pci_save_ptm_state(dev);
return pci_save_vc_state(dev);
```

**목적**: 다양한 PCIe 확장 기능 상태를 저장한다.

**설명**:

- pci_save_pcie_state(dev): PCI Express 상태를 저장한다. 오류 발생 시 해당 오류를 반환한다.
- pci_save_pcix_state(dev): PCI-X 상태를 저장한다. 오류 발생 시 해당 오류를 반환한다.
- pci_save_ltr_state(dev): LTR(Latency Tolerance Reporting) 상태를 저장한다.
- pci_save_dpc_state(dev): DPC(Device Power Control) 상태를 저장한다.
- pci_save_aer_state(dev): AER(Advanced Error Reporting) 상태를 저장한다.
- pci_save_ptm_state(dev): PTM(Precision Time Measurement) 상태를 저장한다.
- pci_save_vc_state(dev): VC(Virtual Channel) 상태를 저장하고, 반환한다.

# 상세 설명

1. **PCI 구성 공간 읽기**

- pci_read_config_dword 함수는 PCI 장치의 구성 공간에서 지정된 오프셋에서 4바이트(DWORD)를 읽어온다.
- 이 함수는 PCI 버스에서 지정된 장치의 레지스터 값을 읽어오는데 사용된다.

1. **디버그 메시지 출력**

- pci_dbg 함수는 디버그 메시지를 출력하는데 사용된다.
- 이 함수는 장치의 디버그 정보를 커널 로그에 기록하여 디버깅을 용이하게 한다.

1. **PCIe 상태 저장 함수들**

- 각 `pci_save_*_state` 함수는 특정 PCIe 확장 기능의 상태를 저장한다.
- 이 함수들은 각각의 확장 기능에 대한 설정을 읽어와 저장하는 역할을 한다.

# 반환 값

- 함수가 성공적으로 완료되면 마지막으로 호출된 pci_save_vc_state 함수의 반환 값을 반환한다.
- 중간에 오류가 발생하면 해당 오류 코드를 반환하고 함수를 종료한다.

# 결론

pci_save_state 함수는 PCI 장치의 구성 공간과 다양한 PCIe 확장 상태를 저장하는 중요한 함수이다. 이는 시스템 절전 모드 전환이나 장치 재설정 시 현재 상태를 나중에 복원하기 위해 필요하다. 이 함수는 각 단계에서 발생할 수 있는 오류를 처리하고, 오류가 발생하면 적절히 반환하여 시스템 안정성을 유지한다.