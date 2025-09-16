

`softnet_data.poll_list`만 보고 어떻게 각 `napi_struct` 구조체를 찾아 참조하는가?

리눅스 `list_head` 구조체와 연결리스트에 삽입하는 함수는 다음과 같다
```c
// include/linux/types.h
struct list_head {
    struct list_head *next, *prev;
};

// include/linux/list.h
/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *new,
                  struct list_head *prev,
                  struct list_head *next)
{
    if (!__list_add_valid(new, prev, next))
        return;
  
    next->prev = new;
    new->next = next;
    new->prev = prev;
    WRITE_ONCE(prev->next, new);
}
```
이처럼 list_head는 포인터만 들고 있고 다른 데이터를 포함하지 않는다
만약 list_head를 포함하는 구조체를 만든다면 다음과 같을 것이다.
```c
struct napi_struct {
	struct list_head	poll_list;

	unsigned long		state;
	int			(*poll)(struct napi_struct *, int);
};
```

---
#### `Container_of(ptr, type, member)` 매크로
```c
// include/linux/container_of.h
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 * WARNING: any const qualifier of @ptr is lost.
 */
#define container_of(ptr, type, member) ({              \
    void *__mptr = (void *)(ptr);                   \
    static_assert(__same_type(*(ptr), ((type *)0)->member) ||   \
              __same_type(*(ptr), void),            \
              "pointer type mismatch in container_of()");   \
    ((type *)(__mptr - offsetof(type, member))); })

// include/linux/stddef.h
#undef offsetof
#define offsetof(TYPE, MEMBER)  __builtin_offsetof(TYPE, MEMBER)


```
C에서 구조체는 멤버들을 정의한 순서대로 메모리를 할당하기 때문에 구조체 type과 member로 offset을 구하고 list_head의 메모리 주소에서 이것을 빼면 부모 구조체의 주소를 찾을 수 있다.

**`offsetof(TYPE, MEMBER)` 매크로의 이전 구현**
```c
// include/linux/stddef.h
#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif
```
`((TYPE *)0)`: 0번 가상메모리 주소를 `TYPE *`타입으로 캐스팅. 실제로는 잘못된 주소지만 이후에 주소 연산만 하기 때문에 문제 없음
`&((TYPE *)0)->MEMBER)`: 구조체 포인터에서 `MEMBER` 멤버로 접근해서 주소를 연산. 구조체의 메모리 주소가 0이므로 멤버의 주소는 곧 구조체 내에서 멤버의 오프셋임
`((size_t)&((TYPE *)0)->MEMBER)`: 정수형으로 캐스팅

---
## 실제 예시
```c
// net/core/dev.c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	LIST_HEAD(list);
start:
	...
	list_splice_init(&sd->poll_list, &list);

	...
	for (;;) {
		struct napi_struct *n;
		...
		// 실제로 데이터를 들고 오는 부분
		n = list_first_entry(&list, struct napi_struct, poll_list);
		...
```

```c
// include/linux/list.h
/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)
```

```c 
list_first_entry(&list, struct napi_struct, poll_list)
	==>list_first_entry(&(list)->next, struct napi_struct, poll_list)
		==>container_of(&(list)->next, struct napi_struct, poll_list)
			==>(napi_struct *)(&(list)->next) - offsetof(struct napi_struct, poll_list)
```
구현에 따르면 offsetof 매크로의 결과는 0일 것이다. 즉 `(&list)->next`의 메모리 주소와 그 부모 구조체의 메모리 주소가 같다. 
따라서 `list` 의 첫번째 노드의 부모 구조체의 메모리 주소(이 예시에서는 `(&list)->next`의 메모리 주소와 동일하다)를 반환하고, 이를 통해 부모 구조체에 접근할 수 있다. 