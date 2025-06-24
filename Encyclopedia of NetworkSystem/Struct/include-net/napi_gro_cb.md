---
Location: /include/net/gro.h
sticker: ""
---

```c title=napi_gro_cb
struct napi_gro_cb {
	union {
		struct {
			/* Virtual address of skb_shinfo(skb)->frags[0].page + offset. */
			void	*frag0;

			/* Length of frag0. */
			unsigned int frag0_len;
		};

		struct {
			/* used in skb_gro_receive() slow path */
			struct sk_buff *last;

			/* jiffies when first packet was created/queued */
			unsigned long age;
		};
	};

	/* This indicates where we are processing relative to skb->data. */
	int	data_offset;

	/* This is non-zero if the packet cannot be merged with the new skb. */
	u16	flush;

	/* Save the IP ID here and check when we get to the transport layer */
	u16	flush_id;

	/* Number of segments aggregated. */
	u16	count;

	/* Used in ipv6_gro_receive() and foo-over-udp and esp-in-udp */
	u16	proto;

/* Used in napi_gro_cb::free */
#define NAPI_GRO_FREE             1
#define NAPI_GRO_FREE_STOLEN_HEAD 2
	/* portion of the cb set to zero at every gro iteration */
	struct_group(zeroed,

		/* Start offset for remote checksum offload */
		u16	gro_remcsum_start;

		/* This is non-zero if the packet may be of the same flow. */
		u8	same_flow:1;

		/* Used in tunnel GRO receive */
		u8	encap_mark:1;

		/* GRO checksum is valid */
		u8	csum_valid:1;

		/* Number of checksums via CHECKSUM_UNNECESSARY */
		u8	csum_cnt:3;

		/* Free the skb? */
		u8	free:2;

		/* Used in foo-over-udp, set in udp[46]_gro_receive */
		u8	is_ipv6:1;

		/* Used in GRE, set in fou/gue_gro_receive */
		u8	is_fou:1;

		/* Used to determine if flush_id can be ignored */
		u8	is_atomic:1;

		/* Number of gro_receive callbacks this packet already went through */
		u8 recursion_counter:4;

		/* GRO is done by frag_list pointer chaining. */
		u8	is_flist:1;
	);

	/* used to support CHECKSUM_COMPLETE for tunneling protocols */
	__wsum	csum;

	/* L3 offsets */
	union {
		struct {
			u16 network_offset;
			u16 inner_network_offset;
		};
		u16 network_offsets[2];
	};
};
```

> 다해서 48byte 크기의 구조체가 됨. (8byte long, pointer 기준)

**frag0 관련 필드**

- **frag0**: skb_shinfo(skb)->frags[0].page + offset의 가상 주소입니다. 이는 첫 번째 조각(fragment)의 시작 주소를 가리킨다.
- **frag0_len**: 첫 번째 조각의 길이이다.

**last와 age**

- **last**: 느린 경로에서 마지막 skb를 가리킨다.
- **age**: 첫 번째 패킷이 생성되거나 큐잉된 시점의 jiffies 값이다.

**데이터 오프셋과 플래그**

- **data_offset**: 현재 데이터 처리 위치를 나타낸다. 이는 skb->data와의 상대적 위치이다.
- **flush**: 패킷이 새로운 skb와 병합될 수 없는 경우 0이 아닌 값을 가진다.
- **flush_id**: IP ID 값을 저장하고, 트랜스포트 레이어에서 확인할 때 사용한다.
- **count**: 병합된 세그먼트의 수를 나타낸다.
- **proto**: 사용된 프로토콜을 나타낸다. 예를 들어, IPv6, foo-over-udp, esp-in-udp 등이 있다.

**zeroed 그룹**

- **gro_remcsum_start**: 원격 체크섬 오프로드의 시작 오프셋이다.
- **same_flow**: 동일한 흐름인지 여부를 나타낸다.
- **encap_mark**: 터널링 GRO 수신에 사용된다.
- **csum_valid**: GRO 체크섬이 유효한지 여부를 나타낸다.
- **csum_cnt**: CHECKSUM_UNNECESSARY를 통해 검증된 체크섬의 수이다.
- **free**: skb를 해제할지 여부를 나타낸다.
- **is_ipv6**: IPv6를 사용 중인지 여부를 나타낸다.
- **is_fou**: GRE에서 사용되며, fou/gue_gro_receive에서 설정된다.
- **is_atomic**: flush_id를 무시할 수 있는지 여부를 나타낸다.
- **recursion_counter**: 이미 실행된 gro_receive 콜백의 수이다.
- **is_flist**: frag_list 포인터 체이닝을 통해 GRO가 수행되는지 여부를 나타낸다.

**기타 필드**

- **csum**: 터널링 프로토콜을 위한 CHECKSUM_COMPLETE를 지원하는 데 사용된다.
- **network_offsets**: 네트워크 오프셋(내부 및 외부)을 나타낸다.

이 구조체는 주로 네트워크 패킷의 병합과 관련된 다양한 상태와 데이터를 관리하는 데 사용되며, 네트워크 성능 최적화에 중요한 역할을 한다. 이를 통해 효율적인 네트워크 패킷 처리를 지원한다.