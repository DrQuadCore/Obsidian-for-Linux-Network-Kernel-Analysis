---
Location: /drivers/net/ethernet/intel/ice/ice_lan_tx_rx.h
---
```c
union ice_32byte_rx_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 hdr_addr; /* Header buffer address */
			/* bit 0 of hdr_addr is DD bit */
		__le64 rsvd1;
		__le64 rsvd2;
	} read;
	struct {
		struct {
			struct {
				__le16 mirroring_status;
				__le16 l2tag1;
			} lo_dword;
			union {
				__le32 rss; /* RSS Hash */
				__le32 fd_id; /* Flow Director filter ID */
			} hi_dword;
		} qword0;
		struct {
			/* status/error/PTYPE/length */
			__le64 status_error_len;
		} qword1;
		struct {
			__le16 ext_status; /* extended status */
			__le16 rsvd;
			__le16 l2tag2_1;
			__le16 l2tag2_2;
		} qword2;
		struct {
			__le32 reserved;
			__le32 fd_id;
		} qword3;
	} wb; /* writeback */
};
```

>사용되지 않는 union이다. 잘못 작성하였다. 그러나 legacy 버전이므로, 참고가 될까하여 남겨두었다.