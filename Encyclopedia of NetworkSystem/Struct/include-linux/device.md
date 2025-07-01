---
Location: /include/linux/device.h
sticker: ""
---

```c title=device
struct device {
	struct kobject kobj;
	struct device		*parent;

	struct device_private	*p;

	const char		*init_name; /* initial name of the device */
	const struct device_type *type;

	const struct bus_type	*bus;	/* type of bus device is on */
	struct device_driver *driver;	/* which driver has allocated this
					   device */
	void		*platform_data;	/* Platform specific data, device
					   core doesn't touch it */
	void		*driver_data;	/* Driver data, set and get with
					   dev_set_drvdata/dev_get_drvdata */
	struct mutex		mutex;	/* mutex to synchronize calls to
					 * its driver.
					 */

	struct dev_links_info	links;
	struct dev_pm_info	power;
	struct dev_pm_domain	*pm_domain;

#ifdef CONFIG_ENERGY_MODEL
	struct em_perf_domain	*em_pd;
#endif

#ifdef CONFIG_PINCTRL
	struct dev_pin_info	*pins;
#endif
	struct dev_msi_info	msi;
#ifdef CONFIG_DMA_OPS
	const struct dma_map_ops *dma_ops;
#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */
	u64		bus_dma_limit;	/* upstream dma constraint */
	const struct bus_dma_region *dma_range_map;

	struct device_dma_parameters *dma_parms;

	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

#ifdef CONFIG_DMA_DECLARE_COHERENT
	struct dma_coherent_mem	*dma_mem; /* internal for coherent mem
					     override */
#endif
#ifdef CONFIG_DMA_CMA
	struct cma *cma_area;		/* contiguous memory area for dma
					   allocations */
#endif
#ifdef CONFIG_SWIOTLB
	struct io_tlb_mem *dma_io_tlb_mem;
#endif
#ifdef CONFIG_SWIOTLB_DYNAMIC
	struct list_head dma_io_tlb_pools;
	spinlock_t dma_io_tlb_lock;
	bool dma_uses_io_tlb;
#endif
	/* arch specific additions */
	struct dev_archdata	archdata;

	struct device_node	*of_node; /* associated device tree node */
	struct fwnode_handle	*fwnode; /* firmware device node */

#ifdef CONFIG_NUMA
	int		numa_node;	/* NUMA node this device is close to */
#endif
	dev_t			devt;	/* dev_t, creates the sysfs "dev" */
	u32			id;	/* device instance */

	spinlock_t		devres_lock;
	struct list_head	devres_head;

	const struct class	*class;
	const struct attribute_group **groups;	/* optional groups */

	void	(*release)(struct device *dev);
	struct iommu_group	*iommu_group;
	struct dev_iommu	*iommu;

	struct device_physical_location *physical_location;

	enum device_removable	removable;

	bool			offline_disabled:1;
	bool			offline:1;
	bool			of_node_reused:1;
	bool			state_synced:1;
	bool			can_match:1;
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	bool			dma_coherent:1;
#endif
#ifdef CONFIG_DMA_OPS_BYPASS
	bool			dma_ops_bypass : 1;
#endif
};
```

struct device는 리눅스 커널에서 사용되는 중요한 구조체로, 다양한 장치(device)의 정보를 관리하고 제어하는 데 사용된다. 이 구조체는 장치의 속성, 상태, 드라이버와의 연계, DMA 설정, 전원 관리 등 다양한 측면을 포괄한다. 각 필드는 특정한 기능이나 정보를 나타내며, 이를 통해 커널이 장치를 효율적으로 관리할 수 있게 한다.
# **주요 필드 설명**

## 1. **기본 정보**

- struct kobject kobj: 커널 객체(kobject)로, 장치를 sysfs에 노출하고 관리하는 데 사용된다.
- struct device `*parent`: 부모 장치에 대한 포인터로, 장치 계층 구조를 형성하는 데 사용된다.
- const char `*init_name`: 장치의 초기 이름.
- const struct device_type `*type`: 장치 유형을 나타내는 구조체 포인터.

## 2. **버스와 드라이버**

- const struct bus_type `*bus`: 장치가 연결된 버스 유형.
- struct device_driver `*driver`: 장치를 관리하는 드라이버에 대한 포인터.
- void `*platform_data`: 플랫폼 특화 데이터를 저장하는 포인터.
- void `*driver_data`: 드라이버 특화 데이터를 저장하는 포인터로, dev_set_drvdata와 dev_get_drvdata 함수를 통해 접근할 수 있다.

## 3. **동기화 및 전원 관리**

- struct mutex mutex: 장치 드라이버 호출을 동기화하는 뮤텍스.
- struct dev_pm_info power: 전원 관리 정보.
- struct dev_pm_domain `*pm_domain`: 전원 관리 도메인에 대한 포인터.

## 4. **DMA 관련**

- const struct dma_map_ops `*dma_ops`: DMA 맵핑 연산에 대한 포인터.
- u64 `*dma_mask`: DMA 마스크로, 장치가 사용할 수 있는 DMA 주소 범위를 나타낸다.
- u64 coherent_dma_mask: 일관된 DMA 매핑을 위한 마스크.
- u64 bus_dma_limit: 업스트림 DMA 제한.
- const struct bus_dma_region `*dma_range_map`: DMA 범위 맵.
- struct device_dma_parameters `*dma_parms`: DMA 매개변수.
- struct list_head dma_pools: DMA 풀 리스트.
- struct dma_coherent_mem `*dma_mem`: 일관된 DMA 메모리 오버라이드.
- struct cma `*cma_area`: DMA 할당을 위한 연속 메모리 영역.
- struct io_tlb_mem `*dma_io_tlb_mem`: IO TLB 메모리.
- struct list_head dma_io_tlb_pools: IO TLB 풀 리스트.
- spinlock_t dma_io_tlb_lock: IO TLB 락.
- bool dma_uses_io_tlb: IO TLB 사용 여부.

## 5. **NUMA와 장치 트리**

- struct device_node *of_node: 장치 트리 노드.
- struct fwnode_handle `*fwnode`: 펌웨어 장치 노드.
- int numa_node: 장치가 가까운 NUMA 노드.

## 6. **장치 인스턴스 및 식별자**

- dev_t devt: 장치 번호.
- u32 id: 장치 인스턴스 ID.
- const struct class *class: 장치 클래스.
- const struct attribute_group `**groups`: 선택적 속성 그룹.

## 7. **리소스 및 잠금**

- spinlock_t devres_lock: 장치 리소스 잠금.
- struct list_head devres_head: 장치 리소스 리스트.

## 8. **IOMMU와 물리적 위치**

- struct iommu_group `*iommu_group`: IOMMU 그룹.
- struct dev_iommu `*iommu`: IOMMU 정보.
- struct device_physical_location `*physical_location`: 물리적 위치.

## 9. **기타**

- void `(*release)`(struct device `*dev`): 장치가 해제될 때 호출되는 함수 포인터.
- enum device_removable removable: 장치 제거 가능 여부.
- bool offline_disabled: 오프라인 비활성화 여부.
- bool offline: 오프라인 여부.
- bool of_node_reused: 노드 재사용 여부.
- bool state_synced: 상태 동기화 여부.
- bool can_match: 일치 가능 여부.
- bool dma_coherent: DMA 일관성 여부.
- bool dma_ops_bypass: DMA 연산 우회 여부.

# **결론**

struct device는 리눅스 커널에서 다양한 장치의 상태와 속성을 관리하는 핵심 데이터 구조체이다. 이 구조체는 장치 계층 구조를 형성하고, 버스 및 드라이버와의 연계를 제공하며, 전원 관리, DMA 설정, NUMA 노드, 장치 트리 등의 다양한 기능을 포함한다. 이 구조체를 통해 커널은 장치의 효율적인 관리와 제어를 수행할 수 있다.