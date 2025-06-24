---
Location: /drivers/net/ethernet/intel/ice/ice_type.h
---

```c title=ice_hw
/* Port hardware description */
struct ice_hw {
	u8 __iomem *hw_addr;
	void *back;
	struct ice_aqc_layer_props *layer_info;
	struct ice_port_info *port_info;
	/* PSM clock frequency for calculating RL profile params */
	u32 psm_clk_freq;
	u64 debug_mask;		/* bitmap for debug mask */
	enum ice_mac_type mac_type;

	u16 fd_ctr_base;	/* FD counter base index */

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;

	u8 pf_id;		/* device profile info */
	enum ice_phy_model phy_model;

	u16 max_burst_size;	/* driver sets this value */

	/* Tx Scheduler values */
	u8 num_tx_sched_layers;
	u8 num_tx_sched_phys_layers;
	u8 flattened_layers;
	u8 max_cgds;
	u8 sw_entry_point_layer;
	u16 max_children[ICE_AQC_TOPO_MAX_LEVEL_NUM];
	struct list_head agg_list;	/* lists all aggregator */

	struct ice_vsi_ctx *vsi_ctx[ICE_MAX_VSI];
	u8 evb_veb;		/* true for VEB, false for VEPA */
	u8 reset_ongoing;	/* true if HW is in reset, false otherwise */
	struct ice_bus_info bus;
	struct ice_flash_info flash;
	struct ice_hw_dev_caps dev_caps;	/* device capabilities */
	struct ice_hw_func_caps func_caps;	/* function capabilities */

	struct ice_switch_info *switch_info;	/* switch filter lists */

	/* Control Queue info */
	struct ice_ctl_q_info adminq;
	struct ice_ctl_q_info sbq;
	struct ice_ctl_q_info mailboxq;

	u8 api_branch;		/* API branch version */
	u8 api_maj_ver;		/* API major version */
	u8 api_min_ver;		/* API minor version */
	u8 api_patch;		/* API patch version */
	u8 fw_branch;		/* firmware branch version */
	u8 fw_maj_ver;		/* firmware major version */
	u8 fw_min_ver;		/* firmware minor version */
	u8 fw_patch;		/* firmware patch version */
	u32 fw_build;		/* firmware build number */

	struct ice_fwlog_cfg fwlog_cfg;
	bool fwlog_supported; /* does hardware support FW logging? */
	struct ice_fwlog_ring fwlog_ring;

/* Device max aggregate bandwidths corresponding to the GL_PWR_MODE_CTL
 * register. Used for determining the ITR/INTRL granularity during
 * initialization.
 */
#define ICE_MAX_AGG_BW_200G	0x0
#define ICE_MAX_AGG_BW_100G	0X1
#define ICE_MAX_AGG_BW_50G	0x2
#define ICE_MAX_AGG_BW_25G	0x3
	/* ITR granularity for different speeds */
#define ICE_ITR_GRAN_ABOVE_25	2
#define ICE_ITR_GRAN_MAX_25	4
	/* ITR granularity in 1 us */
	u8 itr_gran;
	/* INTRL granularity for different speeds */
#define ICE_INTRL_GRAN_ABOVE_25	4
#define ICE_INTRL_GRAN_MAX_25	8
	/* INTRL granularity in 1 us */
	u8 intrl_gran;

#define ICE_MAX_QUAD			2
#define ICE_QUADS_PER_PHY_E82X		2
#define ICE_PORTS_PER_PHY_E82X		8
#define ICE_PORTS_PER_QUAD		4
#define ICE_PORTS_PER_PHY_E810		4
#define ICE_NUM_EXTERNAL_PORTS		(ICE_MAX_QUAD * ICE_PORTS_PER_QUAD)

	/* Active package version (currently active) */
	struct ice_pkg_ver active_pkg_ver;
	u32 pkg_seg_id;
	u32 pkg_sign_type;
	u32 active_track_id;
	u8 pkg_has_signing_seg:1;
	u8 active_pkg_name[ICE_PKG_NAME_SIZE];
	u8 active_pkg_in_nvm;

	/* Driver's package ver - (from the Ice Metadata section) */
	struct ice_pkg_ver pkg_ver;
	u8 pkg_name[ICE_PKG_NAME_SIZE];

	/* Driver's Ice segment format version and ID (from the Ice seg) */
	struct ice_pkg_ver ice_seg_fmt_ver;
	u8 ice_seg_id[ICE_SEG_ID_SIZE];

	/* Pointer to the ice segment */
	struct ice_seg *seg;

	/* Pointer to allocated copy of pkg memory */
	u8 *pkg_copy;
	u32 pkg_size;

	/* tunneling info */
	struct mutex tnl_lock;
	struct ice_tunnel_table tnl;

	struct udp_tunnel_nic_shared udp_tunnel_shared;
	struct udp_tunnel_nic_info udp_tunnel_nic;

	/* dvm boost update information */
	struct ice_dvm_table dvm_upd;

	/* HW block tables */
	struct ice_blk_info blk[ICE_BLK_COUNT];
	struct mutex fl_profs_locks[ICE_BLK_COUNT];	/* lock fltr profiles */
	struct list_head fl_profs[ICE_BLK_COUNT];

	/* Flow Director filter info */
	int fdir_active_fltr;

	struct mutex fdir_fltr_lock;	/* protect Flow Director */
	struct list_head fdir_list_head;

	/* Book-keeping of side-band filter count per flow-type.
	 * This is used to detect and handle input set changes for
	 * respective flow-type.
	 */
	u16 fdir_fltr_cnt[ICE_FLTR_PTYPE_MAX];

	struct ice_fd_hw_prof **fdir_prof;
	DECLARE_BITMAP(fdir_perfect_fltr, ICE_FLTR_PTYPE_MAX);
	struct mutex rss_locks;	/* protect RSS configuration */
	struct list_head rss_list_head;
	struct ice_mbx_snapshot mbx_snapshot;
	DECLARE_BITMAP(hw_ptype, ICE_FLOW_PTYPE_MAX);
	u8 dvm_ena;
	u16 io_expander_handle;
	u8 cgu_part_number;
};
```

struct ice_hw 구조체는 Intel Ethernet Controller (ICE) 드라이버에서 사용되는 데이터 구조체로, 하드웨어 상태와 설정을 관리하는 역할을 한다. 이 구조체는 다양한 하드웨어 리소스, 설정, 상태 정보를 포함하며, 드라이버가 장치를 초기화하고 제어하는 데 필요한 정보를 제공한다.

# **주요 필드 설명**

## 1. **하드웨어 기본 정보**

- u8 `__iomem` *hw_addr: 메모리 매핑된 하드웨어 주소.
- void `*back`: 드라이버의 백엔드 데이터에 대한 포인터.
- struct ice_aqc_layer_props *layer_info: AQC(Aquanta Clock) 레이어 속성 정보.
- struct ice_port_info *port_info: 포트 정보.
- u32 psm_clk_freq: RL 프로필 매개변수 계산을 위한 PSM 클록 주파수.
- u64 debug_mask: 디버그 마스크 비트맵.
- enum ice_mac_type mac_type: MAC 유형.

## 2. **PCI 정보**

- u16 device_id: 디바이스 ID.
- u16 vendor_id: 벤더 ID.
- u16 subsystem_device_id: 서브시스템 디바이스 ID.
- u16 subsystem_vendor_id: 서브시스템 벤더 ID.
- u8 revision_id: PCI 리비전 ID.
- u8 pf_id: 디바이스 프로필 정보.
- enum ice_phy_model phy_model: PHY 모델.

## 3. **전송 스케줄러**

- u8 num_tx_sched_layers: 전송 스케줄링 레이어 수.
- u8 num_tx_sched_phys_layers: 전송 스케줄링 물리 레이어 수.
- u8 flattened_layers: 평탄화된 레이어 수.
- u8 max_cgds: 최대 CGD 수.
- u8 sw_entry_point_layer: 소프트웨어 진입점 레이어.
- u16 `max_children[ICE_AQC_TOPO_MAX_LEVEL_NUM]`: 각 레벨의 최대 자식 노드 수.
- struct list_head agg_list: 모든 애그리게이터 리스트.

## 4. **VSI(Context) 및 스위치 정보**

- struct ice_vsi_ctx `*vsi_ctx[ICE_MAX_VSI]`: VSI(Context) 배열.
- u8 evb_veb: VEB 또는 VEPA 플래그.
- u8 reset_ongoing: 하드웨어 리셋 진행 여부.
- struct ice_switch_info *switch_info: 스위치 필터 리스트 정보.

## 5. **제어 큐 정보**

- struct ice_ctl_q_info adminq: Admin 큐 정보.
- struct ice_ctl_q_info sbq: SBQ 큐 정보.
- struct ice_ctl_q_info mailboxq: 메일박스 큐 정보.

## 6. **API 및 펌웨어 버전**

- u8 api_branch: API 브랜치 버전.
- u8 api_maj_ver: API 메이저 버전.
- u8 api_min_ver: API 마이너 버전.
- u8 api_patch: API 패치 버전.
- u8 fw_branch: 펌웨어 브랜치 버전.
- u8 fw_maj_ver: 펌웨어 메이저 버전.
- u8 fw_min_ver: 펌웨어 마이너 버전.
- u8 fw_patch: 펌웨어 패치 버전.
- u32 fw_build: 펌웨어 빌드 번호.

## 7. **패키지 및 세그먼트 정보**

- struct ice_pkg_ver active_pkg_ver: 활성 패키지 버전.
- u32 pkg_seg_id: 패키지 세그먼트 ID.
- u32 pkg_sign_type: 패키지 서명 타입.
- u8 `active_pkg_name[ICE_PKG_NAME_SIZE]`: 활성 패키지 이름.
- u8 active_pkg_in_nvm: NVM에 있는 활성 패키지 여부.
- struct ice_pkg_ver pkg_ver: 드라이버 패키지 버전.
- u8 `pkg_name[ICE_PKG_NAME_SIZE]`: 드라이버 패키지 이름.
- struct ice_pkg_ver ice_seg_fmt_ver: 드라이버 Ice 세그먼트 포맷 버전.
- u8 `ice_seg_id[ICE_SEG_ID_SIZE]`: Ice 세그먼트 ID.
- struct ice_seg *seg: Ice 세그먼트에 대한 포인터.
- u8 *pkg_copy: 할당된 패키지 메모리의 포인터.
- u32 pkg_size: 패키지 크기.

## 8. **터널링 및 플로우 디렉터 정보**

- struct mutex tnl_lock: 터널링 정보 보호 뮤텍스.
- struct ice_tunnel_table tnl: 터널 테이블.
- struct udp_tunnel_nic_shared udp_tunnel_shared: 공유된 UDP 터널 정보.
- struct udp_tunnel_nic_info udp_tunnel_nic: UDP 터널 NIC 정보.
- struct ice_dvm_table dvm_upd: DVM 부스트 업데이트 정보.
- struct `ice_blk_info blk[ICE_BLK_COUNT]`: 하드웨어 블록 테이블.
- struct mutex `fl_profs_locks[ICE_BLK_COUNT]`: 필터 프로필 보호 뮤텍스.
- struct list_head `fl_profs[ICE_BLK_COUNT]`: 필터 프로필 리스트.

## 9. **Flow Director 및 RSS**

- int fdir_active_fltr: 활성 Flow Director 필터.
- struct mutex fdir_fltr_lock: Flow Director 보호 뮤텍스.
- struct list_head fdir_list_head: Flow Director 리스트 헤드.
- u16 `fdir_fltr_cnt[ICE_FLTR_PTYPE_MAX]`: 플로우 타입별 필터 수.
- struct ice_fd_hw_prof **fdir_prof: Flow Director 하드웨어 프로필.
- DECLARE_BITMAP(fdir_perfect_fltr, ICE_FLTR_PTYPE_MAX): 완벽 필터 비트맵.
- struct mutex rss_locks: RSS(Reduce Sequence Spoofing) 설정 보호 뮤텍스.
- struct list_head rss_list_head: RSS 리스트 헤드.
- struct ice_mbx_snapshot mbx_snapshot: 메일박스 스냅샷.
- DECLARE_BITMAP(hw_ptype, ICE_FLOW_PTYPE_MAX): 하드웨어 플로우 타입 비트맵.
- u8 dvm_ena: DVM 활성화 플래그.
- u16 io_expander_handle: IO 익스팬더 핸들.
- u8 cgu_part_number: CGU 부품 번호.

# **결론**
struct ice_hw는 Intel Ethernet Controller(ICE) 드라이버에서 하드웨어 상태와 설정을 관리하는 중요한 구조체다. 이 구조체는 하드웨어 리소스, 설정, 상태 정보를 포함하며, 드라이버가 장치를 초기화하고 제어하는 데 필요한 다양한 정보를 제공한다. 이 구조체를 통해 드라이버는 하드웨어를 효율적으로 관리하고, 다양한 기능과 설정을 제어할 수 있다.