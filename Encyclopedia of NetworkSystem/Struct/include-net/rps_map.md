---
Location: /include/net/rps.h
---
```c
 * This structure holds an RPS map which can be of variable length.  The
 * map is an array of CPUs.
 */
struct rps_map {
	unsigned int	len;
	struct rcu_head	rcu;
	u16		cpus[];
};
```