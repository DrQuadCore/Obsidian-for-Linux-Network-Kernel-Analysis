---
Location: /net/ipv4/fib_trie.c
---
```c
#define get_cindex(key, kv) (((key) ^ (kv)->key) >> (kv)->pos)
```

현재 들어온 key 값과 현재 노드가 갖고 있는 prefix (kv->key)의 차이를 XOR로 알아내고, pos만큼 밀어서 현재 노드가 child를 고를 때 사용할 child index를 알아냄. (C bits를 알아내는 과정)

---
trie 탐색 중 현재 노드 n에 도착했을 때 IPv4 주소를 이미 일치한 부분 (i + N + S)와 지금 검사할 부분 (C) + 나중에 사용할 아직 모르는 부분 (u)로 나눠서 처리.

- i : 부모 tp보다 더 상위 노드에서 사용한 비트, 지금 단계에선 고려 X. (prefix)
- N: 부모 tp가 child n을 선택할 때 쓴 child index 구간. 
- S: path compression으로 skip 된 부분
- C: 현재 노드 n이 child를 고를 때 볼 부분. 
- u: 더 아래 노드에서 사용할 비트, 지금 단계에서는 고려 X
- 시작 위치 pos에서부터 bits 개의 비트만을 child index로 사용


```c
/*
 * Consider a node 'n' and its parent 'tp'.
 *
 * Example:
 * _________________________________________________________________
 * | i | i | i | i | i | i | i | N | N | N | S | S | S | S | S | C |
 * -----------------------------------------------------------------
 *  31  30  29  28  27  26  25  24  23  22  21  20  19  18  *17*  16
 *
 * _________________________________________________________________
 * | C | C | C | u | u | u | u | u | u | u | u | u | u | u | u | u |
 * -----------------------------------------------------------------
 *  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
 *
 * tp->pos = 22
 * tp->bits = 3
 * n->pos = 13
 * n->bits = 4
 *
 * First, let's just ignore the bits that come before the parent tp, that is
 * the bits from (tp->pos + tp->bits) to 31. They are *known* but at this
 * point we do not use them for anything.
 *
 * The bits from (tp->pos) to (tp->pos + tp->bits - 1) - "N", above - are the
 * index into the parent's child array. That is, they will be used to find
 * 'n' among tp's children.
 *
 * The bits from (n->pos + n->bits) to (tp->pos - 1) - "S" - are skipped bits
 * for the node n.
 *
 * All the bits we have seen so far are significant to the node n. The rest
 * of the bits are really not needed or indeed known in n->key.
 *
 * The bits from (n->pos) to (n->pos + n->bits - 1) - "C" - are the index into
 * n's child array, and will of course be different for each child.
 *
 * The rest of the bits, from 0 to (n->pos -1) - "u" - are completely unknown
 * at this point.
 */
```

```c
struct key_vector {
	t_key key;
	unsigned char pos;		/* 2log(KEYLENGTH) bits needed */
	unsigned char bits;		/* 2log(KEYLENGTH) bits needed */
	unsigned char slen;
	union {
		/* This list pointer if valid if (pos | bits) == 0 (LEAF) */
		struct hlist_head leaf;
		/* This array is valid if (pos | bits) > 0 (TNODE) */
		DECLARE_FLEX_ARRAY(struct key_vector __rcu *, tnode);
	};
};
```