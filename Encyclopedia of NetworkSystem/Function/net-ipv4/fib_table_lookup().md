---
Parameter:
  - fib_table
  - flowi4
  - fib_result
  - int
Return: int
Location: /net/ipv4/fib_trie.c
---
```c title=fib_table_lookup_함수_코드
/* should be called with rcu_read_lock */
int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
             struct fib_result *res, int fib_flags)
{
    struct trie *t = (struct trie *) tb->tb_data;
#ifdef CONFIG_IP_FIB_TRIE_STATS
    struct trie_use_stats __percpu *stats = t->stats;
#endif
    const t_key key = ntohl(flp->daddr);
    struct key_vector *n, *pn;
    struct fib_alias *fa;
    unsigned long index;
    t_key cindex;
  
    pn = t->kv;
    cindex = 0;
  
    n = get_child_rcu(pn, cindex);
    if (!n) {
        trace_fib_table_lookup(tb->tb_id, flp, NULL, -EAGAIN);
        return -EAGAIN;
    }
  
#ifdef CONFIG_IP_FIB_TRIE_STATS
    this_cpu_inc(stats->gets);
#endif
  
    /* Step 1: Travel to the longest prefix match in the trie */
    for (;;) {
        index = get_cindex(key, n);
  
        /* This bit of code is a bit tricky but it combines multiple
         * checks into a single check.  The prefix consists of the
         * prefix plus zeros for the "bits" in the prefix. The index
         * is the difference between the key and this value.  From
         * this we can actually derive several pieces of data.
         *   if (index >= (1ul << bits))
         *     we have a mismatch in skip bits and failed
         *   else
         *     we know the value is cindex
         *
         * This check is safe even if bits == KEYLENGTH due to the
         * fact that we can only allocate a node with 32 bits if a
         * long is greater than 32 bits.
         */
        if (index >= (1ul << n->bits))
            break;
  
        /* we have found a leaf. Prefixes have already been compared */
        if (IS_LEAF(n))
            goto found;
  
        /* only record pn and cindex if we are going to be chopping
         * bits later.  Otherwise we are just wasting cycles.
         */
        if (n->slen > n->pos) {
            pn = n;
            cindex = index;
        }
  
        n = get_child_rcu(n, index);
        if (unlikely(!n))
            goto backtrace;
    }
  
    /* Step 2: Sort out leaves and begin backtracing for longest prefix */
    for (;;) {
        /* record the pointer where our next node pointer is stored */
        struct key_vector __rcu **cptr = n->tnode;
  
        /* This test verifies that none of the bits that differ
         * between the key and the prefix exist in the region of
         * the lsb and higher in the prefix.
         */
        if (unlikely(prefix_mismatch(key, n)) || (n->slen == n->pos))
            goto backtrace;
  
        /* exit out and process leaf */
        if (unlikely(IS_LEAF(n)))
            break;
  
        /* Don't bother recording parent info.  Since we are in
         * prefix match mode we will have to come back to wherever
         * we started this traversal anyway
         */
  
        while ((n = rcu_dereference(*cptr)) == NULL) {
backtrace:
#ifdef CONFIG_IP_FIB_TRIE_STATS
            if (!n)
                this_cpu_inc(stats->null_node_hit);
#endif
            /* If we are at cindex 0 there are no more bits for
             * us to strip at this level so we must ascend back
             * up one level to see if there are any more bits to
             * be stripped there.
             */
            while (!cindex) {
                t_key pkey = pn->key;
  
                /* If we don't have a parent then there is
                 * nothing for us to do as we do not have any
                 * further nodes to parse.
                 */
                if (IS_TRIE(pn)) {
                    trace_fib_table_lookup(tb->tb_id, flp,
                                   NULL, -EAGAIN);
                    return -EAGAIN;
                }
#ifdef CONFIG_IP_FIB_TRIE_STATS
                this_cpu_inc(stats->backtrack);
#endif
                /* Get Child's index */
                pn = node_parent_rcu(pn);
                cindex = get_index(pkey, pn);
            }
  
            /* strip the least significant bit from the cindex */
            cindex &= cindex - 1;
  
            /* grab pointer for next child node */
            cptr = &pn->tnode[cindex];
        }
    }
  
found:
    /* this line carries forward the xor from earlier in the function */
    index = key ^ n->key;
  
    /* Step 3: Process the leaf, if that fails fall back to backtracing */
    hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {
        struct fib_info *fi = fa->fa_info;
        struct fib_nh_common *nhc;
        int nhsel, err;
  
        if ((BITS_PER_LONG > KEYLENGTH) || (fa->fa_slen < KEYLENGTH)) {
            if (index >= (1ul << fa->fa_slen))
                continue;
        }
        if (fa->fa_dscp &&
            inet_dscp_to_dsfield(fa->fa_dscp) != flp->flowi4_tos)
            continue;
        /* Paired with WRITE_ONCE() in fib_release_info() */
        if (READ_ONCE(fi->fib_dead))
            continue;
        if (fa->fa_info->fib_scope < flp->flowi4_scope)
            continue;
        fib_alias_accessed(fa);
        err = fib_props[fa->fa_type].error;
        if (unlikely(err < 0)) {
out_reject:
#ifdef CONFIG_IP_FIB_TRIE_STATS
            this_cpu_inc(stats->semantic_match_passed);
#endif
            trace_fib_table_lookup(tb->tb_id, flp, NULL, err);
            return err;
        }
        if (fi->fib_flags & RTNH_F_DEAD)
            continue;
  
        if (unlikely(fi->nh)) {
            if (nexthop_is_blackhole(fi->nh)) {
                err = fib_props[RTN_BLACKHOLE].error;
                goto out_reject;
            }
  
            nhc = nexthop_get_nhc_lookup(fi->nh, fib_flags, flp,
                             &nhsel);
            if (nhc)
                goto set_result;
            goto miss;
        }
  
        for (nhsel = 0; nhsel < fib_info_num_path(fi); nhsel++) {
            nhc = fib_info_nhc(fi, nhsel);
  
            if (!fib_lookup_good_nhc(nhc, fib_flags, flp))
                continue;
set_result:
            if (!(fib_flags & FIB_LOOKUP_NOREF))
                refcount_inc(&fi->fib_clntref);
  
            res->prefix = htonl(n->key);
            res->prefixlen = KEYLENGTH - fa->fa_slen;
            res->nh_sel = nhsel;
            res->nhc = nhc;
            res->type = fa->fa_type;
            res->scope = fi->fib_scope;
            res->fi = fi;
            res->table = tb;
            res->fa_head = &n->leaf;
#ifdef CONFIG_IP_FIB_TRIE_STATS
            this_cpu_inc(stats->semantic_match_passed);
#endif
            trace_fib_table_lookup(tb->tb_id, flp, nhc, err);
  
            return err;
        }
    }
miss:
#ifdef CONFIG_IP_FIB_TRIE_STATS
    this_cpu_inc(stats->semantic_match_miss);
#endif
    goto backtrace;
}
```

>여러가지 새로 보이는 구조체가 많아서 나중에 한번 정리해야 할 것이다.

>`trie`자료구조를 통해 라우팅 테이블을 저장하고, 관리하고, 탐색하고있었다. 이 자료구조는 문자열을 저장하고 효율적으로 탐색하기 위해 고안된 자료구조로, 따로 공부해보아야 할 것이다.
>해당 구조에 대한 도식은 sock 노트에 있다.
>
>우선 `key`는 최종 목적지인 `flp->daddr`이다. `key_vector`타입으로는 `*n`과 `*pn`이 있는데, 이는 각각 자식노드와 부모노드를 가르키기 위한 포인터이다.
>가장 먼저 `for`문을 들어가기 전에 `n = get_child_rcu(pn, cindex)`를 통해 첫번째 자식 노드를 가져오게 된다. 왜냐면 위에서 `cindex = 0`으로 초기화 하였기 때문이다.

```c
/* To understand this stuff, an understanding of keys and all their bits is
 * necessary. Every node in the trie has a key associated with it, but not
 * all of the bits in that key are significant.
 *
 * Consider a node 'n' and its parent 'tp'.
 *
 * If n is a leaf, every bit in its key is significant. Its presence is
 * necessitated by path compression, since during a tree traversal (when
 * searching for a leaf - unless we are doing an insertion) we will completely
 * ignore all skipped bits we encounter. Thus we need to verify, at the end of
 * a potentially successful search, that we have indeed been walking the
 * correct key path.
 *
 * Note that we can never "miss" the correct key in the tree if present by
 * following the wrong path. Path compression ensures that segments of the key
 * that are the same for all keys with a given prefix are skipped, but the
 * skipped part *is* identical for each node in the subtrie below the skipped
 * bit! trie_insert() in this implementation takes care of that.
 *
 * if n is an internal node - a 'tnode' here, the various parts of its key
 * have many different meanings.
 *
 * Example:
 * _________________________________________________________________
 * | i | i | i | i | i | i | i | N | N | N | S | S | S | S | S | C |
 * -----------------------------------------------------------------
 *  31  30  29  28  27  26  25  24  23  22  21  20  19  18  17  16
 *
 * _________________________________________________________________
 * | C | C | C | u | u | u | u | u | u | u | u | u | u | u | u | u |
 * -----------------------------------------------------------------
 *  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
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
 * of the bits are really not needed or indeed known in n->key
 *
 * The bits from (n->pos) to (n->pos + n->bits - 1) - "C" - are the index into
 * n's child array, and will of course be different for each child.
 *
 * The rest of the bits, from 0 to (n->pos -1) - "u" - are completely unknown
 * at this point.
 */
```

https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux
fib path compressed trie - routing search와 관련하여 아주 명확하게 설명이 들어있는 참고 자료이다.

##### LPC-trie
----
--요약--
>보통의 trie 자료구조 같다면 각 자리마다 노드로 나뉘게 될 것이다. 그러나 라우팅 테이블의 경우 각 자리 비트를 기준으로 해야할 것이기 때문에 이는 상당한 메모리 낭비와 많은 노드를 사용하게 한다. 거기에다가 필요없는 비트 비교연산이 많이 있을 것이다.
>따라서 *path compression*을 사용하게 된다. 이는 각 노드마다 하나의 child를 가져야 함이 삭제되었다. (라우팅 엔트리가 있는 경우는 제외하고) 그리고 각 노드들은 이제 얼마나 많은 비트를 스킵하였는지 알려주는 새로운 변수를 가지게 된다. 이러한 trie 자료구조는 `Patricia trie` 혹은 `radix tree`로 알려져 있다. 
>![[Pasted image 20240904095723 1.png]]
>또한, *level compression* 또한 사용하고 있는데,  trie 구조에서 노드가 많은 부분을 찾아내어 그 child 노드를 0과 1로 나뉘는게 아니라 다루는 비트를 2개 이상으로 함으로써, n개의 비트를 다룰 때, 2^n 개의 자식 노드들이 존재하도록 하는 방법이다.
>![[Pasted image 20240904100752 1.png]]
>이러한 trie를 LC-trie 혹은 LPC-trie라고 부르고, radix tree 보다 더 높은 탐색 성능을 제공한다.
>
>휴리스틱한 부분은 해당 노드가 얼마나 많은 비트를 다루어야 할지 결정하는 것이다. 리눅스에서는 비어있지 않은 자식 노드가 전체 자식 노드의 50%보다 많을 경우 해당 노드가 추가적인 비트를 다루게 된다. 반면 그 비율이 25% 이하라면 해당 노드는 본인이 책임지는 비트에 대한 책임을 잃게 된다. 이러한 값은 튜닝할 수 없다.(아마 유저 레벨에서 config하는 것을 말하는 것으로 보인다.)
>
>![[Pasted image 20240904101222 1.png]]
>리눅스에서는 위와 같이 구현되고 있다.
>https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux
>위의 링크는 리눅스 커널 버전 별로 `fib_lookup()` 함수의 성능 벤치마크를 정리한 사이트이다.
>
>https://docs.kernel.org/networking/fib_trie.html
>https://nscpolteksby.ac.id/ebook/files/Ebook/Computer%20Engineering/Linux%20Kernel%20Networking%20-%20Implementation%20(2014)/chapter%205%20The%20IPv4%20Routing%20Subsystem.pdf
>추가 참고자료 사이트

##### LPC-trie 끝

>이어서 함수를 보자면, `get_cindex(key, n)`을 호출하고 있다. 이 함수는 `#define`으로 `/net/ipv4/fib_trie.c`에 정의되어 있다. 단순하게 `((key)^(n)->key) >> (n)->pos`를 하게 된다. 이는 현재 라우팅을 해야 할 `key`값과 본인 노드의 키 값인 `n->key`를 우선 XOR 연산을 하게 되고, 이후 `pos`만큼 left shift 하게 된다. 그렇다면 상위 비트에 남은 값은 스킵한 비트들과 자식 노드들의 array에 대한 index 값을 가지는 비트들이 남게 된다. 이 때 이 둘을 구분하는 마스크의 역할을 하는 변수는 해당 노드의 `bits`라는 멤버 변수이다.
>
>그 후 만약 `index >= (1ul << n->bits)`라면 `break`이 걸리게 되는데, 이 때 index는 앞서 `get_cindex()`함수를 통해서 얻은 값이다. 만약 위의 조건이 만족한다면, 이는 스킵한 비트들 중에서 mismatch가 일어났다는 뜻이므로, 이는 해당 노드에서 탐색을 실패했다는 의미이다. 따라서 `break`으로 빠지게 되는 것이다. 따라서 바로 아래의 새로운 `for`무한 루프에 빠지게 된다.
>
>만약 해당 노드가 LEAF라면 이 때는 `goto found;`를 통해 `found:`라벨로 향하게 된다.
>
> 만약 `n->slen` 이 `n->pos`보다 크다면, 해당 노드를 parent로써 기억하게 한다. 이렇게 하는 이유는 `slen`이 `pos`보다 크다는 것은 더 비교할 비트들이 남아있다는 뜻이기 때문이다. `slen`에 대하여 찾아보니 일단은 subnet mask의 길이를 저장하고 있는 것으로 보였다. 따라서 그저 `key`값으로 저장된 라우팅 테이블에서 어디까지가 네트워크 주소를 표현하고 있는지 알 수 있다.
> 
> 그리고 해당 index를 가지고 자식 노드를 불러오고, 만약 자식 노드가 없다면 이 때는 백트랙킹을 통해 상위 부모 노드로 가게 된다.
> 
> 또 다른 `for` 무한루프가 시작되고 있다. 여기는 위의 루프에서 앞서 스킵했던 비트 중에 일치하지 않는 부분이 있어서 시작되는 부분이다. 혹은 중간에 `backtrace`라는 라벨이 있는데, 이는 자식 노드가 없을 경우에 이 라벨로 오게 된다.
> `**cptr`로 `n->tnode`를 가져오고 있다. 이는 현재 노드의 다음 포인터가 어디에 저장되어 있는지 기록하는 포인터이다.
> 
> 그 다음으로 나오는 `if`문은 해당 노드가 prefix mismatch가 있거나, 노드의 `slen`과 `pos`가 같다면 `backtrace` 라벨로 가게된다.
> 이 테스트는 해당 노드의 그 어떠한 비트도 `key`와 다르지 않다는 것과, 해당`key`의 prefix가 그 prefix의 비트 영역에 있음을 보증한다. 만약 `n->slen`과 `n->pos`의 길이가 같다면, 해당 노드에 대해서는 더이상 조사할 자식 노드가 없을 것이다. 왜냐면 더이상 하위 라우팅 테이블이 해당 `key`에 대해서 의미가 없기 때문이다.
> 
> 
> 만약 해당 노드가 LEAF라면 for루프를 멈추게 된다.
> `*cptr`을 가져왔을 때 이 것이 `NULL` 이 아니면 이 아래의 while문을 계속하여 반복하게 되는데,
> 우선 `cindex`가 0이 아닐때까지 while을 반복하게 된다. 만약 `cindex`가 0이라면 해당 노드에서는 더 이상 유효한 노드가 없기 때문이다.
> `pkey`값으로 부모노드의 키 값을 저장하게 되고, 만약 `pn`이 TRIE 노드가 아니라면 더 이상 할 수 있는 것이 없으므로 에러를 리턴하게 된다.
> 이후 `node_parent_rcu()`함수를 통해 해당 노드의 부모노드를 가져오게 된다. 또한 `cindex` 값을 `get_index()`함수로 업데이트하게 된다.
> 이에 의해 `cindex`값이 0이 아니게 된다면 해당 while문을 탈출하여 다음으로 넘어가게 되는데, `cindex &= cindex - 1`을 통해 1인 비트중 LSB를 제거하게 된다. (ex. 10010100 => 10010000)
> 이 `cindex`값을 바탕으로 `cptr = &pn->tnode[cindex]`를 하여 해당 자식노드를 새로운 자식 포인터로 가져오게 된다.
> 
> 이 아래로는 `found:`라벨이다.
> 우선 인덱스 값을 설정하게 되는데, `key ^ n->key`값을 가져오게 된다.
> 또한 hlist를 도는 for문이 나오게 된다.
> 이 아래로는 해당 노드의 `leaf`를 가지고 실행되므로 우선 위의 로직을 이해하기 위해 잠시 멈추었다.
> 
> 함수 이해가 안되서 Net Filter 부분부터 다시 보기로 하였다. 나중에 다시 올 것이다.

>