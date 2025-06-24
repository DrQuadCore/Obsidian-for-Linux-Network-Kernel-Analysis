---
Parameter:
  - pci_dev
Return: void
Location: /drivers/pci/pci.c
---

```c title=pci_set_master()
/**
 * pci_set_master - enables bus-mastering for device dev
 * @dev: the PCI device to enable
 *
 * Enables bus-mastering on the device and calls pcibios_set_master()
 * to do the needed arch specific settings.
 */
void pci_set_master(struct pci_dev *dev)
{
	__pci_set_master(dev, true);
	pcibios_set_master(dev);
}
EXPORT_SYMBOL(pci_set_master);
```

PCI 장치를 버스 마스터로 설정하여 DMA를 수행할 수 있도록 해줌.