---
Parameter:
  - softnet_data
Return: void
Location: /net/core/dev.c
---

```c title=net_rps_action_and_irq_enable()
/*
 * net_rps_action_and_irq_enable sends any pending IPI's for rps.
 * Note: called with local irq disabled, but exits with local irq enabled.
 */
static void net_rps_action_and_irq_enable(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	struct softnet_data *remsd = sd->rps_ipi_list;

	if (remsd) {
		sd->rps_ipi_list = NULL;

		local_irq_enable();

		/* Send pending IPI's to kick RPS processing on remote cpus. */
		net_rps_send_ipi(remsd);
	} else
#endif
		local_irq_enable();
}
```


