---
Parameter:
  - napi_struct
Return: bool
Location: /net/core/dev.c
---

```c title=napi_schedule_prep()
/**
* Test if NAPI routine is already running, and if not mark it as running. 
* This is used as a condition variable to insure only one NAPI poll 
* instance runs. We also make sure there is no pending NAPI disable.
*/

bool napi_schedule_prep(struct napi_struct *n)
{
	unsigned long new, val = READ_ONCE(n->state);

	do {
		if (unlikely(val & NAPIF_STATE_DISABLE))
			return false;
		new = val | NAPIF_STATE_SCHED;

		/* Sets STATE_MISSED bit if STATE_SCHED was already set
		 * This was suggested by Alexander Duyck, as compiler
		 * emits better code than :
		 * if (val & NAPIF_STATE_SCHED)
		 *     new |= NAPIF_STATE_MISSED;
		 */
		new |= (val & NAPIF_STATE_SCHED) / NAPIF_STATE_SCHED *
						   NAPIF_STATE_MISSED;
	} while (!try_cmpxchg(&n->state, &val, new));

	return !(val & NAPIF_STATE_SCHED);
}
EXPORT_SYMBOL(napi_schedule_prep);
```

> `napi_schedule_prep`를 통해 napi 스케쥴링이 가능한지 확인

---
>하나의 napi struct에 대해 하나의 poll 함수만 돌도록 보장하는 함수

`NAPIF_STATE_XXX` flag

``` c
enum {
	NAPI_STATE_SCHED,		/* Poll is scheduled */
	NAPI_STATE_MISSED,		/* reschedule a napi */
	NAPI_STATE_DISABLE,		/* Disable pending */
	
	NAPI_STATE_NPSVC,		/* Netpoll - don't dequeue from poll_list */
	NAPI_STATE_LISTED,		/* NAPI added to system lists */
	NAPI_STATE_NO_BUSY_POLL,	/* Do not add in napi_hash, no busy polling */
	NAPI_STATE_IN_BUSY_POLL,	/* sk_busy_loop() owns this NAPI */
	NAPI_STATE_PREFER_BUSY_POLL,	/* prefer busy-polling over softirq processing*/
	NAPI_STATE_THREADED,		/* The poll is performed inside its own thread*/
	NAPI_STATE_SCHED_THREADED,	/* Napi is currently scheduled in threaded mode */
};
```

```c
	NAPI_STATE_SCHED,		/* 이 NAPI가 poll list에 스케줄된 상태임 */
	NAPI_STATE_MISSED,		/* poll 중 다시 스케줄 요청이 들어옴 */
	NAPI_STATE_DISABLE,		/* NAPI 비활성화 요청이 걸려 있음 */
```

```c
bool napi_schedule_prep(struct napi_struct *n)
{
	unsigned long new, val = READ_ONCE(n->state);
```

- napi struct의 state 값을 읽어와서 val에 저장

```c
	do {
		if (unlikely(val & NAPIF_STATE_DISABLE))
			return false;
		new = val | NAPIF_STATE_SCHED;
```

- napi를 poll list에 추가할 수 있는 상황인지 판단
- `NAPIF_STATE_DISABLE` 이 켜져 있다면, 스케줄링이 불가능하다는 뜻이므로 false 반환  
	- [[napi_disable()]]
- `NAPIF_STATE_DISABLE` 이 켜져 있지 않다면, `NAPIF_STATE_SCHED` flag를 켜서 new에 저장

```c
		new |= (val & NAPIF_STATE_SCHED) / NAPIF_STATE_SCHED *
						   NAPIF_STATE_MISSED;
```

- 이미 해당 napi가 스케줄링 된 상태라면, reschedule을 요청을 위해 `NAPIF_STATE_MISSED` flag를 추가적으로 켬 
	- 이미 스케줄링 상태라면 (val & NAPIF_STATE_SCHED) / NAPIF_STATE_SCHED 값이 1이 됨
	- 나중에 napi_complete_done에서 NAPIF_STATE_MISSED flag를 확인하고, 이 flag가 켜져 있다면 해당 napi를 다시 스케줄링함 [[napi_complete_done()]]

```c
} while (!try_cmpxchg(&n->state, &val, new));
```

- compare and exchange
- n->state 값이 val과 같다면, n->state에 new 값을 저장 
	- 성공 시 return true, 실패 시 return false 

```c
	return !(val & NAPIF_STATE_SCHED);
```

- val에는 처음에 읽어왔던 napi struct의 state 값이 저장돼 있음
- val & NAPIF_STATE_SCHED가 true라는 것은 이 napi가 이미 스케줄링 된 상태였다는 것을 의미
	- poll list에 같은 napi가 중복되어 들어가지 않도록 return false
- val & NAPIF_STATE_SCHED가 false라는 것은 이전에 스케줄링 된 적이 없다는 것을 의미
	- poll list에 추가 가능하므로 return true