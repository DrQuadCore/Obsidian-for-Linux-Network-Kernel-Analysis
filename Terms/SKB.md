## SKB 
### 구조
packet을 수신하면 네트워크 장치드라이버가 netdev_alloc_skb 함수를 호출하여 sk_buff 구조체를 할당한다. [[sk_buff]]

```c title=sk_buff_diagram
/*
 * @head: Head of buffer
 * @data: Data head pointer
 * @tail: Tail pointer
 * @end: End pointer
 *
 *                                  ---------------
 *                                 | sk_buff       |
 *                                  ---------------
 *     ,---------------------------  + head
 *    /          ,-----------------  + data
 *   /          /      ,-----------  + tail
 *  |          |      |            , + end
 *  |          |      |           |
 *  v          v      v           v
 *   -----------------------------------------------
 *  | headroom | data |  tailroom | skb_shared_info |
 *   -----------------------------------------------
 *                                 + [page frag]
 *                                 + [page frag]
 *                                 + [page frag]
 *                                 + [page frag]       ---------
 *                                 + frag_list    --> | sk_buff |
 *                                                     ---------
 *
 */
```

skb 안에는 head, data, tail, end pointer가 존재한다. 각 pointer는 다음을 가리킨다. 

- head pointer: 버퍼의 시작 주소
- data pointer: 실제 payload의 시작 주소
- tail pointer: payload의 끝 주소
- end pointer: 버퍼의 끝

skb_shard_info는 end 뒤쪽에 있는 구조체이다.  skb->shared_info 형태로 접근하는 것이 아니라skb_shinfo(skb) 매크로를 통해서만 가능하다.

```c
#define skb_shinfo(SKB)	((struct skb_shared_info *)(skb_end_pointer(SKB)))
```

skb_shared_info  구조체는 다음과 같이 정의돼 있다. 

```c
/* This data is invariant across clones and lives at
 * the end of the header data, ie. at skb->end.
 */
struct skb_shared_info {
	__u8		flags;
	__u8		meta_len;
	__u8		nr_frags; // Number of fragments
	__u8		tx_flags;
	unsigned short	gso_size; 
	/* Warning: this field is not always filled in (UFO)! */
	unsigned short	gso_segs;
	struct sk_buff	*frag_list;
	union {
		struct skb_shared_hwtstamps hwtstamps;
		struct xsk_tx_metadata_compl xsk_meta;
	};
	unsigned int	gso_type;
	u32		tskey;

	/*
	 * Warning : all fields before dataref are cleared in __alloc_skb()
	 */
	atomic_t	dataref;
	unsigned int	xdp_frags_size;

	/* Intermediate layers must ensure that destructor_arg
	 * remains valid until skb destructor */
	void *		destructor_arg;

	/* must be last field, see pskb_expand_head() */
	skb_frag_t	frags[MAX_SKB_FRAGS]; // Fragment array
};

typedef struct skb_frag_struct {
    struct page *page;        // Pointer to memory page
    __u32 page_offset;        // Offset within the page
    __u32 size;              // Size of this fragment
} skb_frag_t;
```

frag_list는 skb들의 list이고 frags는 page fragment들의 list이다. 

### 왜?
Ethernet 헤더, IP 헤더, Transport layer 헤더나 작은 크기의 payload는 skb 안에 연속된 메모리 버퍼에 저장된다.  즉 크기가 작은 데이터들은 보통 skb 안에 linear 하게 저장된다. 

반면, payload가 커서 linear buffer에 다 들어가지 못하는 경우에는, 이 data를 skb의 linear 영역에 담지 않고 fragment 형태로 저장한다. 즉, 실제 payload가 담긴 page의 일부 정보를 skb_frag_t로 가리켜서 저장하는 것이다. 큰 payload를 여러 physical page fragment로 표현하면, skb는 해당 page를 그대로 참조하기만 하면 되므로 별도의 데이터 copy 과정을 피할 수 있다. 

```
Complete sk_buff Memory Organization:

Main SKB Buffer:
+----------+------------------+------------------+----------+
| headroom |   linear data    |     tailroom     |shared_info|
+----------+------------------+------------------+----------+
^          ^                  ^                  ^
|          |                  |                  |
head       data               tail               end
           |<--- headlen ---->|
           |<------- total linear space ------->|

Fragment Pages (referenced by shared_info):
Page 1:                    Page 2:                    Page N:
+------------------+      +------------------+      +------------------+
| Fragment Data 1  |      | Fragment Data 2  |      | Fragment Data N  |
+------------------+      +------------------+      +------------------+
^                         ^                         ^
|                         |                         |
frags[0].page             frags[1].page             frags[n-1].page
offset: frags[0].offset   offset: frags[1].offset   ...
size:   frags[0].size     size:   frags[1].size     ...
```

frag_list는 frags[]와 다르게 page fragment가 아니라 서로 다른 skb 자체를 이어붙일 때 사용한다. 보통 큰 packet을 여러 skb로 나누어 관리해야 할 때 사용한다. 예를 들어, GSO가 켜져 있으면, skb를 만드는 과정에서 큰 payload를 여러 skb 조각들로 나누고 이들을 frag_list로 연결할 수 있다. 즉, frag_list를 통해 하나의 큰 skb를 실제로는 여러 작은 skb들의 체인처럼 이룰 수 있다. [[주요 개념 구조도]]

[Understanding sk_buff: Linear and Fragment Data Organization in Linux Kernel Networking](https://www.linkedin.com/pulse/understanding-skbuff-linear-fragment-data-organization-david-zhu-aoqqc)

> 2025/08/21 스터디
> Q. frags는 언제 어떻게 생기는지
> A. skb에 frags가 채워지는 과정은 [[ice_clean_rx_irq()]]함수에서 호출되는 [[ice_construct_skb()]]내부에서 일어난다.
