---
Parameter:
  - net
  - flowi4
  - fib_result
  - unsigned int
Return: int
Location: /include/net/fib.h
---
```c
static inline int fib_lookup(struct net *net, const struct flowi4 *flp,
                 struct fib_result *res, unsigned int flags)
{
    struct fib_table *tb;
    int err = -ENETUNREACH;
  
    rcu_read_lock();
  
    tb = fib_get_table(net, RT_TABLE_MAIN);
    if (tb)
        err = fib_table_lookup(tb, flp, res, flags | FIB_LOOKUP_NOREF); // [[fib_table_lookup()]]
  
    if (err == -EAGAIN)
        err = -ENETUNREACH;
  
    rcu_read_unlock();
  
    return err;
}
```

>주어진 `flowi4` 구조체와 `fib_result`구조체를 세팅하는 함수. 주어진 `net`을 parameter로 사용하여 `fib_get_table()`함수를 호출하고, 여기서 `fib_table`을 얻게 된다.
>테이블을 얻는 `fib_get_table()`함수의 로직은 간단하다. 인자로 `RT_TABLE_MAIN`을 가지고 들어왔는데, 함수 내부에서는 `RT_TABLE_LOCAL` 여부를 바탕으로 `&net->ipv4.fib_table_hash[]`에서 index를 `TABLE_LOCAL_INDEX` 혹은 `TABLE_MAIN_INDEX`로 집어 넣게 된다.
>그 후 해당 포인터를 가지고 `tb_hlist`를 가져와서 그 첫번째 entry를 가져와서 여기에 해당하는 구조체를 `container_of`함수로 불러오고, 이를 반환하게 된다. 따라서 `fib_table`타입의 결과값을 얻을 수 있게 된다.
>
>이 테이블을 가지고 `fib_table_lookup()`함수를 호출하여 주어진 테이블을 lookup하여 포워딩을 위한 fib를 찾게 된다.

[[fib_table_lookup()]]

---
fib_result 구조체 세팅은 table을 탐색하며 이루어진다. fib_result 구조체의 정의는 다음과 같이 되어있다.

```c
struct fib_result {
	__be32			prefix;
	unsigned char		prefixlen;
	unsigned char		nh_sel; 
	unsigned char		type; // 패킷 처리 방식 (포워딩 or 로컬 전달 or 폐기)
	unsigned char		scope; 
	u32			tclassid;
	struct fib_nh_common	*nhc; // 이번 lookup에서 선택된 nexthop 
	struct fib_info		*fi; // 라우팅 테이블의 엔트리 
	struct fib_table	*table; // fib table을 가리키는 포인터
	struct hlist_head	*fa_head;
};
```

fib_lookup() 함수는 fib_get_table() 함수로 fib table을 불러와 fib_table_lookup() 함수로 table을 탐색한다.