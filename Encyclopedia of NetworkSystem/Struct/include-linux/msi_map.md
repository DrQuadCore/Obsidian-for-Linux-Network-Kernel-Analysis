---
Location: /include/linux/msi_api.h
sticker: ""
---

```c title=msi_map
/**
 * msi_map - Mapping between MSI index and Linux interrupt number
 * @index:	The MSI index, e.g. slot in the MSI-X table or
 *		a software managed index if >= 0. If negative
 *		the allocation function failed and it contains
 *		the error code.
 * @virq:	The associated Linux interrupt number
 */
struct msi_map {
	int	index;
	int	virq;
};
```

virq는 관련된 interrupt number, index는 msi-x의 테이블이나 소프트웨어로 관리되는 인덱스임.