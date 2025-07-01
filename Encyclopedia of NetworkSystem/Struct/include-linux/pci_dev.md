---
Location: /include/linux/pci.h
sticker: ""
---

```c title=pci_dev
/* The pci_dev structure describes PCI devices */
struct pci_dev {
	struct list_head bus_list;	/* Node in per-bus list */
	struct pci_bus	*bus;		/* Bus this device is on */
	struct pci_bus	*subordinate;	/* Bus this device bridges to */

	void		*sysdata;	/* Hook for sys-specific extension */
	struct proc_dir_entry *procent;	/* Device entry in /proc/bus/pci */
	struct pci_slot	*slot;		/* Physical slot this device is in */

	unsigned int	devfn;		/* Encoded device & function index */
	unsigned short	vendor;
	unsigned short	device;
	unsigned short	subsystem_vendor;
	unsigned short	subsystem_device;
	unsigned int	class;		/* 3 bytes: (base,sub,prog-if) */
	u8		revision;	/* PCI revision, low byte of class word */
	u8		hdr_type;	/* PCI header type (`multi' flag masked out) */
#ifdef CONFIG_PCIEAER
	u16		aer_cap;	/* AER capability offset */
	struct aer_stats *aer_stats;	/* AER stats for this device */
#endif
#ifdef CONFIG_PCIEPORTBUS
	struct rcec_ea	*rcec_ea;	/* RCEC cached endpoint association */
	struct pci_dev  *rcec;          /* Associated RCEC device */
#endif
	u32		devcap;		/* PCIe Device Capabilities */
	u8		pcie_cap;	/* PCIe capability offset */
	u8		msi_cap;	/* MSI capability offset */
	u8		msix_cap;	/* MSI-X capability offset */
	u8		pcie_mpss:3;	/* PCIe Max Payload Size Supported */
	u8		rom_base_reg;	/* Config register controlling ROM */
	u8		pin;		/* Interrupt pin this device uses */
	u16		pcie_flags_reg;	/* Cached PCIe Capabilities Register */
	unsigned long	*dma_alias_mask;/* Mask of enabled devfn aliases */

	struct pci_driver *driver;	/* Driver bound to this device */
	u64		dma_mask;	/* Mask of the bits of bus address this
					   device implements.  Normally this is
					   0xffffffff.  You only need to change
					   this if your device has broken DMA
					   or supports 64-bit transfers.  */

	struct device_dma_parameters dma_parms;

	pci_power_t	current_state;	/* Current operating state. In ACPI,
					   this is D0-D3, D0 being fully
					   functional, and D3 being off. */
	u8		pm_cap;		/* PM capability offset */
	unsigned int	imm_ready:1;	/* Supports Immediate Readiness */
	unsigned int	pme_support:5;	/* Bitmask of states from which PME#
					   can be generated */
	unsigned int	pme_poll:1;	/* Poll device's PME status bit */
	unsigned int	d1_support:1;	/* Low power state D1 is supported */
	unsigned int	d2_support:1;	/* Low power state D2 is supported */
	unsigned int	no_d1d2:1;	/* D1 and D2 are forbidden */
	unsigned int	no_d3cold:1;	/* D3cold is forbidden */
	unsigned int	bridge_d3:1;	/* Allow D3 for bridge */
	unsigned int	d3cold_allowed:1;	/* D3cold is allowed by user */
	unsigned int	mmio_always_on:1;	/* Disallow turning off io/mem
						   decoding during BAR sizing */
	unsigned int	wakeup_prepared:1;
	unsigned int	skip_bus_pm:1;	/* Internal: Skip bus-level PM */
	unsigned int	ignore_hotplug:1;	/* Ignore hotplug events */
	unsigned int	hotplug_user_indicators:1; /* SlotCtl indicators
						      controlled exclusively by
						      user sysfs */
	unsigned int	clear_retrain_link:1;	/* Need to clear Retrain Link
						   bit manually */
	unsigned int	d3hot_delay;	/* D3hot->D0 transition time in ms */
	unsigned int	d3cold_delay;	/* D3cold->D0 transition time in ms */

#ifdef CONFIG_PCIEASPM
	struct pcie_link_state	*link_state;	/* ASPM link state */
	u16		l1ss;		/* L1SS Capability pointer */
	unsigned int	ltr_path:1;	/* Latency Tolerance Reporting
					   supported from root to here */
#endif
	unsigned int	pasid_no_tlp:1;		/* PASID works without TLP Prefix */
	unsigned int	eetlp_prefix_path:1;	/* End-to-End TLP Prefix */

	pci_channel_state_t error_state;	/* Current connectivity state */
	struct device	dev;			/* Generic device interface */

	int		cfg_size;		/* Size of config space */

	/*
	 * Instead of touching interrupt line and base address registers
	 * directly, use the values stored here. They might be different!
	 */
	unsigned int	irq;
	struct resource resource[DEVICE_COUNT_RESOURCE]; /* I/O and memory regions + expansion ROMs */
	struct resource driver_exclusive_resource;	 /* driver exclusive resource ranges */

	bool		match_driver;		/* Skip attaching driver */

	unsigned int	transparent:1;		/* Subtractive decode bridge */
	unsigned int	io_window:1;		/* Bridge has I/O window */
	unsigned int	pref_window:1;		/* Bridge has pref mem window */
	unsigned int	pref_64_window:1;	/* Pref mem window is 64-bit */
	unsigned int	multifunction:1;	/* Multi-function device */

	unsigned int	is_busmaster:1;		/* Is busmaster */
	unsigned int	no_msi:1;		/* May not use MSI */
	unsigned int	no_64bit_msi:1;		/* May only use 32-bit MSIs */
	unsigned int	block_cfg_access:1;	/* Config space access blocked */
	unsigned int	broken_parity_status:1;	/* Generates false positive parity */
	unsigned int	irq_reroute_variant:2;	/* Needs IRQ rerouting variant */
	unsigned int	msi_enabled:1;
	unsigned int	msix_enabled:1;
	unsigned int	ari_enabled:1;		/* ARI forwarding */
	unsigned int	ats_enabled:1;		/* Address Translation Svc */
	unsigned int	pasid_enabled:1;	/* Process Address Space ID */
	unsigned int	pri_enabled:1;		/* Page Request Interface */
	unsigned int	is_managed:1;		/* Managed via devres */
	unsigned int	is_msi_managed:1;	/* MSI release via devres installed */
	unsigned int	needs_freset:1;		/* Requires fundamental reset */
	unsigned int	state_saved:1;
	unsigned int	is_physfn:1;
	unsigned int	is_virtfn:1;
	unsigned int	is_hotplug_bridge:1;
	unsigned int	shpc_managed:1;		/* SHPC owned by shpchp */
	unsigned int	is_thunderbolt:1;	/* Thunderbolt controller */
	/*
	 * Devices marked being untrusted are the ones that can potentially
	 * execute DMA attacks and similar. They are typically connected
	 * through external ports such as Thunderbolt but not limited to
	 * that. When an IOMMU is enabled they should be getting full
	 * mappings to make sure they cannot access arbitrary memory.
	 */
	unsigned int	untrusted:1;
	/*
	 * Info from the platform, e.g., ACPI or device tree, may mark a
	 * device as "external-facing".  An external-facing device is
	 * itself internal but devices downstream from it are external.
	 */
	unsigned int	external_facing:1;
	unsigned int	broken_intx_masking:1;	/* INTx masking can't be used */
	unsigned int	io_window_1k:1;		/* Intel bridge 1K I/O windows */
	unsigned int	irq_managed:1;
	unsigned int	non_compliant_bars:1;	/* Broken BARs; ignore them */
	unsigned int	is_probed:1;		/* Device probing in progress */
	unsigned int	link_active_reporting:1;/* Device capable of reporting link active */
	unsigned int	no_vf_scan:1;		/* Don't scan for VFs after IOV enablement */
	unsigned int	no_command_memory:1;	/* No PCI_COMMAND_MEMORY */
	unsigned int	rom_bar_overlap:1;	/* ROM BAR disable broken */
	unsigned int	rom_attr_enabled:1;	/* Display of ROM attribute enabled? */
	pci_dev_flags_t dev_flags;
	atomic_t	enable_cnt;	/* pci_enable_device has been called */

	spinlock_t	pcie_cap_lock;		/* Protects RMW ops in capability accessors */
	u32		saved_config_space[16]; /* Config space saved at suspend time */
	struct hlist_head saved_cap_space;
	struct bin_attribute *res_attr[DEVICE_COUNT_RESOURCE]; /* sysfs file for resources */
	struct bin_attribute *res_attr_wc[DEVICE_COUNT_RESOURCE]; /* sysfs file for WC mapping of resources */

#ifdef CONFIG_HOTPLUG_PCI_PCIE
	unsigned int	broken_cmd_compl:1;	/* No compl for some cmds */
#endif
#ifdef CONFIG_PCIE_PTM
	u16		ptm_cap;		/* PTM Capability */
	unsigned int	ptm_root:1;
	unsigned int	ptm_enabled:1;
	u8		ptm_granularity;
#endif
#ifdef CONFIG_PCI_MSI
	void __iomem	*msix_base;
	raw_spinlock_t	msi_lock;
#endif
	struct pci_vpd	vpd;
#ifdef CONFIG_PCIE_DPC
	u16		dpc_cap;
	unsigned int	dpc_rp_extensions:1;
	u8		dpc_rp_log_size;
#endif
#ifdef CONFIG_PCI_ATS
	union {
		struct pci_sriov	*sriov;		/* PF: SR-IOV info */
		struct pci_dev		*physfn;	/* VF: related PF */
	};
	u16		ats_cap;	/* ATS Capability offset */
	u8		ats_stu;	/* ATS Smallest Translation Unit */
#endif
#ifdef CONFIG_PCI_PRI
	u16		pri_cap;	/* PRI Capability offset */
	u32		pri_reqs_alloc; /* Number of PRI requests allocated */
	unsigned int	pasid_required:1; /* PRG Response PASID Required */
#endif
#ifdef CONFIG_PCI_PASID
	u16		pasid_cap;	/* PASID Capability offset */
	u16		pasid_features;
#endif
#ifdef CONFIG_PCI_P2PDMA
	struct pci_p2pdma __rcu *p2pdma;
#endif
#ifdef CONFIG_PCI_DOE
	struct xarray	doe_mbs;	/* Data Object Exchange mailboxes */
#endif
	u16		acs_cap;	/* ACS Capability offset */
	phys_addr_t	rom;		/* Physical address if not from BAR */
	size_t		romlen;		/* Length if not from BAR */
	/*
	 * Driver name to force a match.  Do not set directly, because core
	 * frees it.  Use driver_set_override() to set or clear it.
	 */
	const char	*driver_override;

	unsigned long	priv_flags;	/* Private flags for the PCI driver */

	/* These methods index pci_reset_fn_methods[] */
	u8 reset_methods[PCI_NUM_RESET_METHODS]; /* In priority order */
};
```

struct pci_dev 구조체는 리눅스 커널에서 PCI(Peripheral Component Interconnect) 장치를 나타내는 데이터 구조체이다. 이 구조체는 PCI 장치의 다양한 속성, 상태, 버스 및 드라이버와의 연계, DMA 설정 등을 관리한다. 각 필드는 특정한 기능이나 정보를 나타내며, 이를 통해 커널이 PCI 장치를 효율적으로 관리할 수 있다.

# **주요 필드 설명**

## 1. **버스 및 슬롯 정보**

- struct list_head bus_list: 버스 내 장치 리스트에 대한 노드.
- struct pci_bus `*bus`: 장치가 연결된 버스.
- struct pci_bus `*subordinate`: 브리지 장치가 연결된 하위 버스.
- struct pci_slot `*slot`: 장치가 물리적으로 장착된 슬롯.

## 2. **식별자 및 기본 속성**

- unsigned int devfn: 장치 및 함수 인덱스(장치 번호 및 함수 번호).
- unsigned short vendor: 벤더 ID.
- unsigned short device: 디바이스 ID.
- unsigned short subsystem_vendor: 서브시스템 벤더 ID.
- unsigned short subsystem_device: 서브시스템 디바이스 ID.
- unsigned int class: 장치 클래스(베이스 클래스, 서브 클래스, 프로그래밍 인터페이스).
- u8 revision: PCI 리비전 번호.
- u8 hdr_type: PCI 헤더 타입.

## 3. **PCIe 관련 정보**

- u8 pcie_cap: PCIe capability 오프셋.
- u8 msi_cap: MSI capability 오프셋.
- u8 msix_cap: MSI-X capability 오프셋.
- u8 pcie_mpss: PCIe 최대 페이로드 크기 지원.

## 4. **드라이버 관련**

- struct pci_driver *driver: 장치에 바인딩된 드라이버.
- u64 dma_mask: DMA 주소 마스크.
- struct device_dma_parameters dma_parms: DMA 매개변수.

## 5. **전원 관리**

- pci_power_t current_state: 현재 운영 상태(D0-D3).
- u8 pm_cap: 전원 관리 capability 오프셋.
- unsigned int imm_ready: 즉시 준비 상태 지원 여부.
- unsigned int pme_support: PME#을 생성할 수 있는 상태 비트마스크.
- unsigned int pme_poll: PME 상태 비트를 폴링할지 여부.
- unsigned int d1_support: D1 저전력 상태 지원 여부.
- unsigned int d2_support: D2 저전력 상태 지원 여부.
- unsigned int no_d1d2: D1 및 D2 상태 금지 여부.
- unsigned int no_d3cold: D3cold 상태 금지 여부.

## 6. **리소스 및 상태 관리**

- struct resource `resource[DEVICE_COUNT_RESOURCE]`: I/O 및 메모리 영역 + 확장 ROM.
- unsigned int irq: 인터럽트 라인.
- struct device dev: 일반 장치 인터페이스.
- int cfg_size: 구성 공간 크기.
- atomic_t enable_cnt: pci_enable_device가 호출된 횟수.

## 7. **상태 플래그**

- unsigned int transparent: 감산 디코드 브리지 여부.
- unsigned int io_window: 브리지가 I/O 윈도우를 가지고 있는지 여부.
- unsigned int pref_window: 브리지가 선호 메모리 윈도우를 가지고 있는지 여부.
- unsigned int is_busmaster: 버스 마스터인지 여부.
- unsigned int no_msi: MSI 사용 불가 여부.
- unsigned int msi_enabled: MSI 사용 여부.
- unsigned int msix_enabled: MSI-X 사용 여부.

## 8. **IOMMU 및 DMA 관련**

- u16 ats_cap: ATS Capability 오프셋.
- u16 pasid_cap: PASID Capability 오프셋.
- unsigned int ats_enabled: ATS(Address Translation Service) 활성화 여부.
- unsigned int pasid_enabled: PASID(Process Address Space ID) 활성화 여부.

## 9. **PCIe 확장 및 고급 기능**

- u16 acs_cap: ACS(Access Control Services) Capability 오프셋.
- unsigned int pasid_no_tlp: PASID가 TLP(TLP Prefix) 없이 작동하는지 여부.
- unsigned int eetlp_prefix_path: E2E TLP Prefix 지원 여부.
- pci_channel_state_t error_state: 현재 연결 상태.
- u32 `saved_config_space[16]`: 절전 시 구성 공간 저장.
- struct hlist_head saved_cap_space: 저장된 capability 공간.

## 10. **플랫폼 및 시스템 정보**

- void `*sysdata`: 시스템 특화 확장을 위한 훅.
- struct proc_dir_entry `*procent`: /proc/bus/pci의 장치 엔트리.
- struct device_node `*of_node`: 장치 트리 노드.
- struct fwnode_handle `*fwnode`: 펌웨어 장치 노드.
- int numa_node: NUMA 노드.

## 11. **기타**

- const char `*driver_override`: 강제 매칭을 위한 드라이버 이름.
- unsigned long priv_flags: PCI 드라이버를 위한 개인 플래그.
- u8 `reset_methods[PCI_NUM_RESET_METHODS]`: PCI 리셋 메서드 우선순위.

# **결론**

struct pci_dev는 리눅스 커널에서 PCI 장치를 나타내는 핵심 데이터 구조체로, PCI 장치의 다양한 속성, 상태, 버스 및 드라이버와의 연계, DMA 설정 등을 관리한다. 이 구조체를 통해 커널은 PCI 장치를 효율적으로 관리하고 제어할 수 있으며, PCI 장치의 특성과 요구에 맞게 다양한 기능을 제공할 수 있다.