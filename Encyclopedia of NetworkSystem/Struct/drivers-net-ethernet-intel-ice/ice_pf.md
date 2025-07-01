---
Location: /drivers/net/ethernet/intel/ice/ice.h
---

```c title=ice_pf
struct ice_pf {
	struct pci_dev *pdev;

	struct devlink_region *nvm_region;
	struct devlink_region *sram_region;
	struct devlink_region *devcaps_region;

	/* devlink port data */
	struct devlink_port devlink_port;

	/* OS reserved IRQ details */
	struct msix_entry *msix_entries;
	struct ice_irq_tracker irq_tracker;
	/* First MSIX vector used by SR-IOV VFs. Calculated by subtracting the
	 * number of MSIX vectors needed for all SR-IOV VFs from the number of
	 * MSIX vectors allowed on this PF.
	 */
	u16 sriov_base_vector;
	unsigned long *sriov_irq_bm;	/* bitmap to track irq usage */
	u16 sriov_irq_size;		/* size of the irq_bm bitmap */

	u16 ctrl_vsi_idx;		/* control VSI index in pf->vsi array */

	struct ice_vsi **vsi;		/* VSIs created by the driver */
	struct ice_vsi_stats **vsi_stats;
	struct ice_sw *first_sw;	/* first switch created by firmware */
	u16 eswitch_mode;		/* current mode of eswitch */
	struct dentry *ice_debugfs_pf;
	struct dentry *ice_debugfs_pf_fwlog;
	/* keep track of all the dentrys for FW log modules */
	struct dentry **ice_debugfs_pf_fwlog_modules;
	struct ice_vfs vfs;
	DECLARE_BITMAP(features, ICE_F_MAX);
	DECLARE_BITMAP(state, ICE_STATE_NBITS);
	DECLARE_BITMAP(flags, ICE_PF_FLAGS_NBITS);
	DECLARE_BITMAP(misc_thread, ICE_MISC_THREAD_NBITS);
	unsigned long *avail_txqs;	/* bitmap to track PF Tx queue usage */
	unsigned long *avail_rxqs;	/* bitmap to track PF Rx queue usage */
	unsigned long serv_tmr_period;
	unsigned long serv_tmr_prev;
	struct timer_list serv_tmr;
	struct work_struct serv_task;
	struct mutex avail_q_mutex;	/* protects access to avail_[rx|tx]qs */
	struct mutex sw_mutex;		/* lock for protecting VSI alloc flow */
	struct mutex tc_mutex;		/* lock to protect TC changes */
	struct mutex adev_mutex;	/* lock to protect aux device access */
	struct mutex lag_mutex;		/* protect ice_lag struct in PF */
	u32 msg_enable;
	struct ice_ptp ptp;
	struct gnss_serial *gnss_serial;
	struct gnss_device *gnss_dev;
	u16 num_rdma_msix;		/* Total MSIX vectors for RDMA driver */
	u16 rdma_base_vector;

	/* spinlock to protect the AdminQ wait list */
	spinlock_t aq_wait_lock;
	struct hlist_head aq_wait_list;
	wait_queue_head_t aq_wait_queue;
	bool fw_emp_reset_disabled;

	wait_queue_head_t reset_wait_queue;

	u32 hw_csum_rx_error;
	u32 oicr_err_reg;
	struct msi_map oicr_irq;	/* Other interrupt cause MSIX vector */
	struct msi_map ll_ts_irq;	/* LL_TS interrupt MSIX vector */
	u16 max_pf_txqs;	/* Total Tx queues PF wide */
	u16 max_pf_rxqs;	/* Total Rx queues PF wide */
	u16 num_lan_msix;	/* Total MSIX vectors for base driver */
	u16 num_lan_tx;		/* num LAN Tx queues setup */
	u16 num_lan_rx;		/* num LAN Rx queues setup */
	u16 next_vsi;		/* Next free slot in pf->vsi[] - 0-based! */
	u16 num_alloc_vsi;
	u16 corer_count;	/* Core reset count */
	u16 globr_count;	/* Global reset count */
	u16 empr_count;		/* EMP reset count */
	u16 pfr_count;		/* PF reset count */

	u8 wol_ena : 1;		/* software state of WoL */
	u32 wakeup_reason;	/* last wakeup reason */
	struct ice_hw_port_stats stats;
	struct ice_hw_port_stats stats_prev;
	struct ice_hw hw;
	u8 stat_prev_loaded:1; /* has previous stats been loaded */
	u8 rdma_mode;
	u16 dcbx_cap;
	u32 tx_timeout_count;
	unsigned long tx_timeout_last_recovery;
	u32 tx_timeout_recovery_level;
	char int_name[ICE_INT_NAME_STR_LEN];
	char int_name_ll_ts[ICE_INT_NAME_STR_LEN];
	struct auxiliary_device *adev;
	int aux_idx;
	u32 sw_int_count;
	/* count of tc_flower filters specific to channel (aka where filter
	 * action is "hw_tc <tc_num>")
	 */
	u16 num_dmac_chnl_fltrs;
	struct hlist_head tc_flower_fltr_list;

	u64 supported_rxdids;

	__le64 nvm_phy_type_lo; /* NVM PHY type low */
	__le64 nvm_phy_type_hi; /* NVM PHY type high */
	struct ice_link_default_override_tlv link_dflt_override;
	struct ice_lag *lag; /* Link Aggregation information */

	struct ice_eswitch eswitch;
	struct ice_esw_br_port *br_port;

#define ICE_INVALID_AGG_NODE_ID		0
#define ICE_PF_AGG_NODE_ID_START	1
#define ICE_MAX_PF_AGG_NODES		32
	struct ice_agg_node pf_agg_node[ICE_MAX_PF_AGG_NODES];
#define ICE_VF_AGG_NODE_ID_START	65
#define ICE_MAX_VF_AGG_NODES		32
	struct ice_agg_node vf_agg_node[ICE_MAX_VF_AGG_NODES];
	struct ice_dplls dplls;
	struct device *hwmon_dev;
};
```

Intel의 네트워크 인터페이스 카드(NIC) 드라이버에서 사용되는 데이터 구조체로, 물리적 기능(PF: Physical Function)과 관련된 다양한 정보를 저장하고 관리한다. 이 구조체는 PF와 관련된 리소스, 상태, 설정 등을 관리하는 역할을 한다.

# **주요 필드 설명**

## 1. **하드웨어 기본 정보**

- struct pci_dev `*pdev`: PCI 장치 구조체 포인터로, 장치의 PCI 정보를 포함한다.
- struct devlink_region `*nvm_region`, `*sram_region`, `*devcaps_region`: 다양한 메모리 영역(NVM, SRAM, DevCaps) 관련 정보를 저장하는 devlink 지역.
## **2. devlink 포트 데이터**

- struct devlink_port devlink_port: devlink 포트와 관련된 데이터.

## **3. IRQ(인터럽트) 관련**

- struct msix_entry `*msix_entries`: MSIX 엔트리 배열.
- struct ice_irq_tracker irq_tracker: IRQ 추적기.
- u16 sriov_base_vector: SR-IOV VFs에 사용되는 첫 번째 MSIX 벡터.
- unsigned long `*sriov_irq_bm`: IRQ 사용을 추적하는 비트맵.
- u16 sriov_irq_size: IRQ 비트맵의 크기.

## **4. VSI(가상 스위치 인스턴스) 관련**

- u16 ctrl_vsi_idx: 제어 VSI 인덱스.
- struct ice_vsi `**vsi`: 드라이버에 의해 생성된 VSI 배열.
- struct ice_vsi_stats `**vsi_stats`: VSI 통계 배열.
- struct ice_sw *first_sw: 첫 번째 스위치.

## **5. 디버그 및 상태 추적**

- struct dentry *ice_debugfs_pf: PF 디버그 파일 시스템 엔트리.
- struct dentry *ice_debugfs_pf_fwlog: FW 로그 디버그 파일 시스템 엔트리.
- struct dentry `**ice_debugfs_pf_fwlog_modules`: FW 로그 모듈 디버그 엔트리 배열.
- DECLARE_BITMAP(features, ICE_F_MAX): 기능 비트맵.
- DECLARE_BITMAP(state, ICE_STATE_NBITS): 상태 비트맵.
- DECLARE_BITMAP(flags, ICE_PF_FLAGS_NBITS): 플래그 비트맵.
- DECLARE_BITMAP(misc_thread, ICE_MISC_THREAD_NBITS): 기타 스레드 비트맵.

## **6. 큐 및 리소스 관리**

- unsigned long *avail_txqs: 사용 가능한 Tx 큐 비트맵.
- unsigned long *avail_rxqs: 사용 가능한 Rx 큐 비트맵.
- struct mutex avail_q_mutex: Tx/Rx 큐 접근 보호 뮤텍스.
- struct mutex sw_mutex: VSI 할당 보호 뮤텍스.
- struct mutex tc_mutex: TC 변경 보호 뮤텍스.
- struct mutex adev_mutex: 보조 장치 접근 보호 뮤텍스.
- struct mutex lag_mutex: 링크 어그리게이션 보호 뮤텍스.

## **7. PTP 및 GNSS 관련**

- struct ice_ptp ptp: PTP(Precision Time Protocol) 관련 데이터.
- struct gnss_serial *gnss_serial: GNSS 시리얼 인터페이스.
- struct gnss_device *gnss_dev: GNSS 장치.

## **8. MSIX 및 인터럽트 관리**

- u16 num_rdma_msix: RDMA 드라이버용 MSIX 벡터 수.
- u16 rdma_base_vector: RDMA용 첫 번째 MSIX 벡터.
- spinlock_t aq_wait_lock: AdminQ 대기 목록 보호 스핀락.
- struct hlist_head aq_wait_list: AdminQ 대기 목록.
- wait_queue_head_t aq_wait_queue: AdminQ 대기 큐.
- u16 num_lan_msix: LAN 드라이버용 MSIX 벡터 수.
- u16 num_lan_tx: 설정된 LAN Tx 큐 수.
- u16 num_lan_rx: 설정된 LAN Rx 큐 수.

## 9. **리셋 및 오류 관리**

- u16 corer_count: 코어 리셋 카운트.
- u16 globr_count: 글로벌 리셋 카운트.
- u16 empr_count: EMP 리셋 카운트.
- u16 pfr_count: PF 리셋 카운트.
- u32 hw_csum_rx_error: RX 체크섬 오류.
- u32 oicr_err_reg: OICR 오류 레지스터.
- struct msi_map oicr_irq: 기타 인터럽트 원인 MSIX 벡터.
- struct msi_map ll_ts_irq: LL_TS 인터럽트 MSIX 벡터.

## 10. **링크 상태 및 통계**

- struct ice_hw_port_stats stats: 포트 통계.
- struct ice_hw_port_stats stats_prev: 이전 포트 통계.
- struct ice_hw hw: 하드웨어 정보.
- u8 stat_prev_loaded: 이전 통계 로드 여부.
- u32 tx_timeout_count: Tx 타임아웃 카운트.
- unsigned long tx_timeout_last_recovery: 마지막 Tx 타임아웃 복구 시간.
- u32 tx_timeout_recovery_level: Tx 타임아웃 복구 레벨.
- u8 wol_ena: Wake-on-LAN 활성화 상태.
- u32 wakeup_reason: 마지막 웨이크업 이유.

## 11. **링크 어그리게이션 및 지원**

- struct ice_lag `*lag`: 링크 어그리게이션 정보.
- struct ice_eswitch eswitch: eSwitch 정보.
- struct ice_esw_br_port *br_port: eSwitch 브리지 포트.

## 12. **기타**

- char `int_name[ICE_INT_NAME_STR_LEN]`: 인터럽트 이름.
- char `int_name_ll_ts[ICE_INT_NAME_STR_LEN]`: LL_TS 인터럽트 이름.
- struct auxiliary_device *adev: 보조 장치.
- int aux_idx: 보조 장치 인덱스.
- u32 sw_int_count: 소프트웨어 인터럽트 카운트.
- u16 num_dmac_chnl_fltrs: DMAC 채널 필터 수.
- struct hlist_head tc_flower_fltr_list: TC Flower 필터 목록.
- u64 supported_rxdids: 지원되는 RX DID.
- `__le64` nvm_phy_type_lo: NVM PHY 타입 하위 64비트.
- `__le64` nvm_phy_type_hi: NVM PHY 타입 상위 64비트.
- struct ice_link_default_override_tlv link_dflt_override: 링크 기본 오버라이드.
- struct ice_agg_node `pf_agg_node[ICE_MAX_PF_AGG_NODES]`: PF 어그리게이션 노드.
- struct ice_agg_node `vf_agg_node[ICE_MAX_VF_AGG_NODES]`: VF 어그리게이션 노드.
- struct ice_dplls dplls: DPLL 정보.
- struct device `*hwmon_dev`: 하드웨어 모니터링 장치.

# **결론**

ice_pf 구조체는 Intel의 NIC 드라이버에서 PF와 관련된 다양한 정보를 저장하고 관리하는 역할을 한다. 이 구조체는 장치 초기화, 리소스 관리, 상태 모니터링, 가상 기능 관리, 인터럽트 처리 등 다양한 기능을 포함하며, 드라이버가 장치를 효율적으로 제어하고 운영할 수 있도록 돕는다.