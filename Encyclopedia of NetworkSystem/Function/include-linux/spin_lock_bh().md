``` c
// /include/linux/spinlock.h

static __always_inline void spin_lock_bh(spinlock_t *lock)
{
	raw_spin_lock_bh(&lock->rlock);
}

#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
```

```c
// /kernel/locking/spinlock.c
#ifndef CONFIG_INLINE_SPIN_LOCK_BH
noinline void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)
{
	__raw_spin_lock_bh(lock);
}
EXPORT_SYMBOL(_raw_spin_lock_bh);
#endif
```

```c
// include/linux/spinlock_api_smp.h
static inline void __raw_spin_lock_bh(raw_spinlock_t *lock)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}
```
단계별로 함수를 실행해 `__raw_spin_lock_bh()`가 실행된다.

---
### __local_bh_disable_ip()

`__local_bh_disable_ip()`는 플래그에 따라 실행되는 여러 구현이 있다. 가장 단순한 구현은 다음과 같다.
```c
// include/linux/bottom_half.h
#if defined(CONFIG_PREEMPT_RT) || defined(CONFIG_TRACE_IRQFLAGS)
extern void __local_bh_disable_ip(unsigned long ip, unsigned int cnt);
#else
static __always_inline void __local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
	preempt_count_add(cnt);
	barrier();
}
#endif
```

`preempt_count_add()` 함수 또한 플래그에 따라 복잡한 구현이 있지만 단순한 구현은 다음과 같다.
```c title=preempt_cound_add()
// /include/linux/preempt.h

#if defined(CONFIG_DEBUG_PREEMPT) || defined(CONFIG_TRACE_PREEMPT_TOGGLE)
extern void preempt_count_add(int val);
extern void preempt_count_sub(int val);
#define preempt_count_dec_and_test() \
	({ preempt_count_sub(1); should_resched(0); })
#else
#define preempt_count_add(val)	__preempt_count_add(val)
#define preempt_count_sub(val)	__preempt_count_sub(val)
#define preempt_count_dec_and_test() __preempt_count_dec_and_test()
#endif
```

```c title=__preempt_count_add()
// include/asm-generic/preempt.h
/*
 * The various preempt_count add/sub methods
 */

static __always_inline void __preempt_count_add(int val)
{
	*preempt_count_ptr() += val;
}

static __always_inline volatile int *preempt_count_ptr(void)
{
	return &current_thread_info()->preempt_count;
}
```
결론적으로 현재 실행되는 스레드의 preempt_count값을 `SOFTIRQ_LOCK_OFFSET`만큼 증가시킨다.

```c
/*
 * The preempt_count offset needed for things like:
 *
 *  spin_lock_bh()
 *
 * Which need to disable both preemption (CONFIG_PREEMPT_COUNT) and
 * softirqs, such that unlock sequences of:
 *
 *  spin_unlock();
 *  local_bh_enable();
 *
 * Work as expected.
 */
#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)

#define SOFTIRQ_DISABLE_OFFSET	(2 * SOFTIRQ_OFFSET)

/*
 * The preempt_count offset after spin_lock()
 */
#if !defined(CONFIG_PREEMPT_RT)
#define PREEMPT_LOCK_OFFSET		PREEMPT_DISABLE_OFFSET
#else
/* Locks on RT do not disable preemption */
#define PREEMPT_LOCK_OFFSET		0
#endif

/*
 * Macros to retrieve the current execution context:
 *
 * in_hardirq()		- We're in hard IRQ context
 * in_serving_softirq()	- We're in softirq context
 * in_task()		- We're in task context
 */
#define in_hardirq()		(hardirq_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)

# define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
```
현재 softirq에 있는지 없는지 확인하는 함수`in_serving_softirq()`는 곧 preempt_count()의 값에 `SOFTIRQ_OFFSET`을 비트곱 연산해서 확인하는데, `spin_lock_bh()`함수에서 이 비트를 켰기 때문에 이미 softirq가 시작 중이라고 판단하고 다른 softirq를 실행하지 않는다.