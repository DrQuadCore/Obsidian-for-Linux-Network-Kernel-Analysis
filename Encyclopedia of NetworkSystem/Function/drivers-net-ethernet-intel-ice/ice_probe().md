---
Parameter:
  - pci_dev
  - pci_device_id
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_probe()
/**
 * ice_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in ice_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int
ice_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *ent)
{
	struct device *dev = &pdev->dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int err;

	if (pdev->is_virtfn) {
		dev_err(dev, "can't probe a virtual function\n");
		return -EINVAL;
	}

	/* when under a kdump kernel initiate a reset before enabling the
	 * device in order to clear out any pending DMA transactions. These
	 * transactions can cause some systems to machine check when doing
	 * the pcim_enable_device() below.
	 */
	if (is_kdump_kernel()) {
		pci_save_state(pdev); // [[pci_save_state()]]
		pci_clear_master(pdev); // [[pci_clear_master()]]
		err = pcie_flr(pdev);
		if (err)
			return err;
		pci_restore_state(pdev);
	}

	/* this driver uses devres, see
	 * Documentation/driver-api/driver-model/devres.rst
	 */
	err = pcim_enable_device(pdev);
	if (err)
		return err;

	err = pcim_iomap_regions(pdev, BIT(ICE_BAR0), dev_driver_string(dev));
	if (err) {
		dev_err(dev, "BAR0 I/O map error %d\n", err);
		return err;
	}

	pf = ice_allocate_pf(dev); // [[ice_allocate_pf()]]
	if (!pf)
		return -ENOMEM;

	/* initialize Auxiliary index to invalid value */
	pf->aux_idx = -1;

	/* set up for high or low DMA */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)); // [[dma_set_mask_and_coherent()]]
	if (err) {
		dev_err(dev, "DMA configuration failed: 0x%x\n", err);
		return err;
	}

	pci_set_master(pdev); // [[pci_set_master()]]

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(ICE_DOWN, pf->state);
	/* Disable service task until DOWN bit is cleared */
	set_bit(ICE_SERVICE_DIS, pf->state);

	hw = &pf->hw;
	hw->hw_addr = pcim_iomap_table(pdev)[ICE_BAR0];
	pci_save_state(pdev); // [[pci_save_state()]]

	hw->back = pf;
	hw->port_info = NULL;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);
	ice_set_ctrlq_len(hw);

	pf->msg_enable = netif_msg_init(debug, ICE_DFLT_NETIF_M);

#ifndef CONFIG_DYNAMIC_DEBUG
	if (debug < -1)
		hw->debug_mask = debug;
#endif

	err = ice_init(pf); // [[ice_init()]]
	if (err)
		goto err_init;

	devl_lock(priv_to_devlink(pf));
	err = ice_load(pf); // [[ice_load()]]
	devl_unlock(priv_to_devlink(pf));
	if (err)
		goto err_load;

	err = ice_init_devlink(pf); // [[ice_init_devlink()]]
	if (err)
		goto err_init_devlink;

	return 0;

err_init_devlink:
	devl_lock(priv_to_devlink(pf));
	ice_unload(pf);
	devl_unlock(priv_to_devlink(pf));
err_load:
	ice_deinit(pf);
err_init:
	pci_disable_device(pdev);
	return err;
}
```

[[pci_save_state()]]
[[pci_clear_master()]]
[[ice_allocate_pf()]]
[[dma_set_mask_and_coherent()]]
[[pci_set_master()]]
[[ice_init()]]
[[ice_load()]]
[[ice_init_devlink()]]

ice_probe 함수는 Intel의 NIC(Network Interface Card) 드라이버에서 PCI 장치(PNIC)를 초기화하고 설정하는 과정에서 호출되는 함수이다. 이 함수는 NIC를 시스템에 등록하고, 필요한 리소스를 할당하며, 초기화를 수행한다. 함수의 각 단계와 해당 단계에서 호출되는 함수의 기능을 자세히 설명하겠다.
# 함수 설명

## 0. 함수 선언 및 변수 선언

```c
/**
 * ice_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in ice_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int ice_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *ent)
{
	struct device *dev = &pdev->dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	int err;
```

## 1. 가상 함수 확인

```c
if (pdev->is_virtfn) {
    dev_err(dev, "can't probe a virtual function\\n");
    return -EINVAL;
}
```

**목적**: 장치가 가상 함수(Virtual Function)인지 확인한다.

**설명**: pdev->is_virtfn이 참이면, 가상 함수를 프로브하지 않고 오류 메시지를 출력한 후, -EINVAL을 반환하며 함수를 종료한다.

## 2. **kdump 커널에서의 초기화**

```c
/* when under a kdump kernel initiate a reset before enabling the
* device in order to clear out any pending DMA transactions. These
* transactions can cause some systems to machine check when doing
* the pcim_enable_device() below.
*/
if (is_kdump_kernel()) {
		pci_save_state(pdev);
		pci_clear_master(pdev);
		err = pcie_flr(pdev);
		if (err)
			return err;
		pci_restore_state(pdev);
	}
```

**목적**: kdump 커널에서 장치 초기화 시 남아 있는 DMA 트랜잭션을 정리한다.

**설명**:

- pci_save_state(pdev): 현재 PCI 상태를 저장한다.
- pci_clear_master(pdev): DMA 마스터 비트를 비활성화하여 DMA 트랜잭션을 중지한다.
- pcie_flr(pdev): PCIe 기능 레벨 리셋(FLR)을 수행한다.
- 오류가 발생하면 해당 오류를 반환하고 함수를 종료한다.
- pci_restore_state(pdev): 저장된 PCI 상태를 복원한다.

## 3. **PCI 장치 활성화 및 I/O 매핑**

```c
/* this driver uses devres, see
* Documentation/driver-api/driver-model/devres.rst
*/
err = pcim_enable_device(pdev);
if (err)
    return err;

err = pcim_iomap_regions(pdev, BIT(ICE_BAR0), dev_driver_string(dev));
if (err) {
    dev_err(dev, "BAR0 I/O map error %d\\n", err);
    return err;
}
```

**목적**: PCI 장치를 활성화하고 I/O 메모리에 매핑한다.

**설명**:

- pcim_enable_device(pdev): PCI 장치를 활성화한다. 오류 발생 시 해당 오류를 반환하고 함수를 종료한다.
- pcim_iomap_regions(pdev, BIT(ICE_BAR0), dev_driver_string(dev)): BAR0를 I/O 메모리에 매핑한다. 오류 발생 시 오류 메시지를 출력하고 해당 오류를 반환하며 함수를 종료한다.

## 4. **PF(Physical Function) 구조체 할당 및 초기화**

```c
pf = ice_allocate_pf(dev);
if (!pf)
    return -ENOMEM;
    
/* initialize Auxiliary index to invalid value */
pf->aux_idx = -1;
```

**목적**: PF 구조체를 할당하고 초기화한다.

**설명**:

- ice_allocate_pf(dev): PF 구조체를 할당한다. 할당 실패 시 메모리 부족 오류 -ENOMEM을 반환하며 함수를 종료한다.
- pf->aux_idx = -1: 보조 인덱스를 무효 값으로 초기화한다.

## 5. DMA 설정 및 마스터 설정

```c
/* set up for high or low DMA */
err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
if (err) {
    dev_err(dev, "DMA configuration failed: 0x%x\\n", err);
    return err;
}
pci_set_master(pdev);
```

**목적**: DMA 설정을 수행하고 장치를 DMA 마스터로 설정한다.

**설명**:

- dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)): 64비트 DMA 주소 마스크를 설정한다. 오류 발생 시 오류 메시지를 출력하고 해당 오류를 반환하며 함수를 종료한다.
- pci_set_master(pdev): PCI 장치를 DMA 마스터로 설정한다.

## **6. PF 구조체 설정 및 상태 초기화**

```c
pf->pdev = pdev;
pci_set_drvdata(pdev, pf);
set_bit(ICE_DOWN, pf->state);
/* Disable service task until DOWN bit is cleared */
set_bit(ICE_SERVICE_DIS, pf->state);
```

**목적**: PF 구조체에 PCI 장치 데이터를 설정하고 초기 상태를 설정한다.

**설명**:

- pf->pdev = pdev: PF 구조체에 PCI 장치 데이터를 설정한다.
- pci_set_drvdata(pdev, pf): PCI 장치 데이터에 PF 구조체를 저장한다.
- set_bit(ICE_DOWN, pf->state): 초기 상태를 ICE_DOWN으로 설정한다.
- set_bit(ICE_SERVICE_DIS, pf->state): 서비스 작업을 비활성화한다.

## **7. 하드웨어 정보 설정**

```c
hw = &pf->hw;
hw->hw_addr = pcim_iomap_table(pdev)[ICE_BAR0];
pci_save_state(pdev);

hw->back = pf;
hw->port_info = NULL;
hw->vendor_id = pdev->vendor;
hw->device_id = pdev->device;
pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
hw->subsystem_vendor_id = pdev->subsystem_vendor;
hw->subsystem_device_id = pdev->subsystem_device;
hw->bus.device = PCI_SLOT(pdev->devfn);
hw->bus.func = PCI_FUNC(pdev->devfn);
ice_set_ctrlq_len(hw);
```

**목적**: 하드웨어 정보 구조체를 설정한다.

**설명**:

- hw->hw_addr = pcim_iomap_table(pdev)[ICE_BAR0]: BAR0 주소를 매핑하여 하드웨어 주소를 설정한다.
- pci_save_state(pdev): PCI 상태를 저장한다.
- hw->back = pf: 하드웨어 구조체에 PF 구조체를 설정한다.
- hw->port_info = NULL: 포트 정보를 초기화한다.
- hw->vendor_id = pdev->vendor: 벤더 ID를 설정한다.
- hw->device_id = pdev->device: 디바이스 ID를 설정한다.
- pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id): PCI 리비전 ID를 읽어 설정한다.
- hw->subsystem_vendor_id = pdev->subsystem_vendor: 서브시스템 벤더 ID를 설정한다.
- hw->subsystem_device_id = pdev->subsystem_device: 서브시스템 디바이스 ID를 설정한다.
- hw->bus.device = PCI_SLOT(pdev->devfn): PCI 슬롯 정보를 설정한다.
- hw->bus.func = PCI_FUNC(pdev->devfn): PCI 함수 정보를 설정한다.
- ice_set_ctrlq_len(hw): 제어 큐 길이를 설정한다.

## 8. 디버그 설정

```c
pf->msg_enable = netif_msg_init(debug, ICE_DFLT_NETIF_M);

#ifndef CONFIG_DYNAMIC_DEBUG
if (debug < -1)
    hw->debug_mask = debug;
#endif
```

**목적**: 디버그 메시지 설정을 초기화한다.

**설명**:

- pf->msg_enable = netif_msg_init(debug, ICE_DFLT_NETIF_M): 디버그 메시지 설정을 초기화한다.
- #ifndef CONFIG_DYNAMIC_DEBUG: 동적 디버그가 설정되지 않은 경우,
    - if (debug < -1) hw->debug_mask = debug;: 디버그 레벨을 설정한다.

## 9. 초기화 함수 호출

```c
 	err = ice_init(pf);
	if (err)
		goto err_init;

	devl_lock(priv_to_devlink(pf));
	err = ice_load(pf);
	devl_unlock(priv_to_devlink(pf));
	if (err)
		goto err_load;

	err = ice_init_devlink(pf);
	if (err)
		goto err_init_devlink;
```

**목적**: 다양한 초기화 함수를 호출하여 하드웨어 및 소프트웨어를 초기화한다.

## 10. 정상 완료

```c
return 0;
```

**목적**: 함수가 성공적으로 완료되었음을 알린다.

**설명**: 모든 초기화가 성공적으로 완료되면 0을 반환하여 성공을 알린다.

## 11. 오류 처리 및 정리

```c
err_init_devlink:
	devl_lock(priv_to_devlink(pf));
	ice_unload(pf);
	devl_unlock(priv_to_devlink(pf));
err_load:
	ice_deinit(pf);
err_init:
	pci_disable_device(pdev);
	return err;
```

**목적**: 초기화 과정에서 오류가 발생했을 때 적절히 정리하고 오류를 반환한다.
# 결론

`ice_probe` 함수는 PCI 장치 초기화의 핵심 부분으로, 가상 함수 확인, kdump 커널 지원, PCI 장치 활성화, PF 구조체 할당 및 초기화, DMA 설정, 디버그 설정, 다양한 초기화 함수 호출 등을 수행하며, 각 단계에서 발생하는 오류를 적절히 처리하고 정리한다. 이 함수는 NIC 드라이버가 시스템에 올바르게 등록되고 작동할 수 있도록 하는 중요한 역할을 한다.