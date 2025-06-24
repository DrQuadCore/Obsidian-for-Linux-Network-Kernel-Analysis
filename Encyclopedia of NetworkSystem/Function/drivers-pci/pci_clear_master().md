---
Parameter:
  - pci_dev
Return: void
Location: /drivers/pci/pci.c
---

```c title=pci_clear_master()
void pci_clear_master(struct pci_dev *dev)
{
	__pci_set_master(dev, false);
}
EXPORT_SYMBOL(pci_clear_master);
```

