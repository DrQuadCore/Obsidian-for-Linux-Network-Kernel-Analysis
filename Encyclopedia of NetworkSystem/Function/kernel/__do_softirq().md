---
Parameter:
  - void
Return: void
Location: /kernel/softirq.c
---

```c title=__do_softirq()
asmlinkage __visible void __softirq_entry __do_softirq(void)
{
	handle_softirqs(false); // [[Encyclopedia of NetworkSystem/Function/kernel/handle_softirqs().md|handle_softirqs()]]
}
```

[[Encyclopedia of NetworkSystem/Function/kernel/handle_softirqs().md|handle_softirqs()]]