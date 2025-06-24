---
Location: /include/net/rps.h
---
```c
 * The rps_dev_flow_table structure contains a table of flow mappings.
 */
struct rps_dev_flow_table {
	unsigned int		mask;
	struct rcu_head		rcu;
	struct rps_dev_flow	flows[];
};
```