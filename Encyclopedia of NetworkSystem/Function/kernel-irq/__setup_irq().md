---
Parameter:
  - int
  - irq_desc
  - irqaction
Return: int
Location: /kernel/irq/manage.c
---

```c title=__setup_irq()
/*
 * Internal function to register an irqaction - typically used to
 * allocate special interrupts that are part of the architecture.
 *
 * Locking rules:
 *
 * desc->request_mutex	Provides serialization against a concurrent free_irq()
 *   chip_bus_lock	Provides serialization for slow bus operations
 *     desc->lock	Provides serialization against hard interrupts
 *
 * chip_bus_lock and desc->lock are sufficient for all other management and
 * interrupt related functions. desc->request_mutex solely serializes
 * request/free_irq().
 */
 static int
__setup_irq(unsigned int irq, struct irq_desc *desc, struct irqaction *new)
{
	struct irqaction *old, **old_ptr;
	unsigned long flags, thread_mask = 0;
	int ret, nested, shared = 0;

	if (!desc)
		return -EINVAL;

	if (desc->irq_data.chip == &no_irq_chip)
		return -ENOSYS;
	if (!try_module_get(desc->owner))
		return -ENODEV;

	new->irq = irq;

	/*
	 * If the trigger type is not specified by the caller,
	 * then use the default for this interrupt.
	 */
	if (!(new->flags & IRQF_TRIGGER_MASK))
		new->flags |= irqd_get_trigger_type(&desc->irq_data);

	/*
	 * Check whether the interrupt nests into another interrupt
	 * thread.
	 */
	nested = irq_settings_is_nested_thread(desc);
	if (nested) {
		if (!new->thread_fn) {
			ret = -EINVAL;
			goto out_mput;
		}
		/*
		 * Replace the primary handler which was provided from
		 * the driver for non nested interrupt handling by the
		 * dummy function which warns when called.
		 */
		new->handler = irq_nested_primary_handler;
	} else {
		if (irq_settings_can_thread(desc)) {
			ret = irq_setup_forced_threading(new);
			if (ret)
				goto out_mput;
		}
	}
	/*
	 * Create a handler thread when a thread function is supplied
	 * and the interrupt does not nest into another interrupt
	 * thread.
	 */
	if (new->thread_fn && !nested) {
		ret = setup_irq_thread(new, irq, false); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/setup_irq_thread().md|setup_irq_thread()]]
		if (ret)
			goto out_mput;
		if (new->secondary) {
			ret = setup_irq_thread(new->secondary, irq, true); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/setup_irq_thread().md|setup_irq_thread()]]
			if (ret)
				goto out_thread;
		}
	}

	/*
	 * Drivers are often written to work w/o knowledge about the
	 * underlying irq chip implementation, so a request for a
	 * threaded irq without a primary hard irq context handler
	 * requires the ONESHOT flag to be set. Some irq chips like
	 * MSI based interrupts are per se one shot safe. Check the
	 * chip flags, so we can avoid the unmask dance at the end of
	 * the threaded handler for those.
	 */
	if (desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)
		new->flags &= ~IRQF_ONESHOT;

	/*
	 * Protects against a concurrent __free_irq() call which might wait
	 * for synchronize_hardirq() to complete without holding the optional
	 * chip bus lock and desc->lock. Also protects against handing out
	 * a recycled oneshot thread_mask bit while it's still in use by
	 * its previous owner.
	 */
	mutex_lock(&desc->request_mutex); // [[Encyclopedia of NetworkSystem/Function/kernel-locking/mutex_lock().md|mutex_lock()]]

	/*
	 * Acquire bus lock as the irq_request_resources() callback below
	 * might rely on the serialization or the magic power management
	 * functions which are abusing the irq_bus_lock() callback,
	 */
	chip_bus_lock(desc); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/chip_bus_lock().md|chip_bus_lock()]]

	/* First installed action requests resources. */
	if (!desc->action) {
		ret = irq_request_resources(desc);
		if (ret) {
			pr_err("Failed to request resources for %s (irq %d) on irqchip %s\n",
			       new->name, irq, desc->irq_data.chip->name);
			goto out_bus_unlock;
		}
	}
	// 만약 desc→action이 없다면 irq_request_resources()로 자원을 요청한다.
	// old 포인터를 통해 만약 해당하는 irq에 actioin이 있다면 이를 공유 할 수 있는지 확인하고, 
	// 위배하였다면 관련된 처리를 한다.

	/*
	 * The following block of code has to be executed atomically
	 * protected against a concurrent interrupt and any of the other
	 * management calls which are not serialized via
	 * desc->request_mutex or the optional bus lock.
	 */
	raw_spin_lock_irqsave(&desc->lock, flags);
	old_ptr = &desc->action;
	old = *old_ptr;
	if (old) {
		/*
		 * Can't share interrupts unless both agree to and are
		 * the same type (level, edge, polarity). So both flag
		 * fields must have IRQF_SHARED set and the bits which
		 * set the trigger type must match. Also all must
		 * agree on ONESHOT.
		 * Interrupt lines used for NMIs cannot be shared.
		 */
		unsigned int oldtype;

		if (desc->istate & IRQS_NMI) {
			pr_err("Invalid attempt to share NMI for %s (irq %d) on irqchip %s.\n",
				new->name, irq, desc->irq_data.chip->name);
			ret = -EINVAL;
			goto out_unlock;
		}

		/*
		 * If nobody did set the configuration before, inherit
		 * the one provided by the requester.
		 */
		if (irqd_trigger_type_was_set(&desc->irq_data)) {
			oldtype = irqd_get_trigger_type(&desc->irq_data);
		} else {
			oldtype = new->flags & IRQF_TRIGGER_MASK;
			irqd_set_trigger_type(&desc->irq_data, oldtype);
		}

		if (!((old->flags & new->flags) & IRQF_SHARED) ||
		    (oldtype != (new->flags & IRQF_TRIGGER_MASK)))
			goto mismatch;

		if ((old->flags & IRQF_ONESHOT) &&
		    (new->flags & IRQF_COND_ONESHOT))
			new->flags |= IRQF_ONESHOT;
		else if ((old->flags ^ new->flags) & IRQF_ONESHOT)
			goto mismatch;

		/* All handlers must agree on per-cpuness */
		if ((old->flags & IRQF_PERCPU) !=
		    (new->flags & IRQF_PERCPU))
			goto mismatch;

		/* add new interrupt at end of irq queue */
		do {
			/*
			 * Or all existing action->thread_mask bits,
			 * so we can find the next zero bit for this
			 * new action.
			 */
			thread_mask |= old->thread_mask;
			old_ptr = &old->next;
			old = *old_ptr;
		} while (old);
		shared = 1;
	}

	/*
	 * Setup the thread mask for this irqaction for ONESHOT. For
	 * !ONESHOT irqs the thread mask is 0 so we can avoid a
	 * conditional in irq_wake_thread().
	 */
	if (new->flags & IRQF_ONESHOT) {
		/*
		 * Unlikely to have 32 resp 64 irqs sharing one line,
		 * but who knows.
		 */
		if (thread_mask == ~0UL) {
			ret = -EBUSY;
			goto out_unlock;
		}
		/*
		 * The thread_mask for the action is or'ed to
		 * desc->thread_active to indicate that the
		 * IRQF_ONESHOT thread handler has been woken, but not
		 * yet finished. The bit is cleared when a thread
		 * completes. When all threads of a shared interrupt
		 * line have completed desc->threads_active becomes
		 * zero and the interrupt line is unmasked. See
		 * handle.c:irq_wake_thread() for further information.
		 *
		 * If no thread is woken by primary (hard irq context)
		 * interrupt handlers, then desc->threads_active is
		 * also checked for zero to unmask the irq line in the
		 * affected hard irq flow handlers
		 * (handle_[fasteoi|level]_irq).
		 *
		 * The new action gets the first zero bit of
		 * thread_mask assigned. See the loop above which or's
		 * all existing action->thread_mask bits.
		 */
		new->thread_mask = 1UL << ffz(thread_mask);

	} else if (new->handler == irq_default_primary_handler &&
		   !(desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)) {
		/*
		 * The interrupt was requested with handler = NULL, so
		 * we use the default primary handler for it. But it
		 * does not have the oneshot flag set. In combination
		 * with level interrupts this is deadly, because the
		 * default primary handler just wakes the thread, then
		 * the irq lines is reenabled, but the device still
		 * has the level irq asserted. Rinse and repeat....
		 *
		 * While this works for edge type interrupts, we play
		 * it safe and reject unconditionally because we can't
		 * say for sure which type this interrupt really
		 * has. The type flags are unreliable as the
		 * underlying chip implementation can override them.
		 */
		pr_err("Threaded irq requested with handler=NULL and !ONESHOT for %s (irq %d)\n",
		       new->name, irq);
		ret = -EINVAL;
		goto out_unlock;
	}
	 	if (!shared) {
		/* Setup the type (level, edge polarity) if configured: */
		if (new->flags & IRQF_TRIGGER_MASK) {
			ret = __irq_set_trigger(desc,
						new->flags & IRQF_TRIGGER_MASK); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/__irq_set_trigger().md|__irq_set_trigger()]]

			if (ret)
				goto out_unlock;
		}

		/*
		 * Activate the interrupt. That activation must happen
		 * independently of IRQ_NOAUTOEN. request_irq() can fail
		 * and the callers are supposed to handle
		 * that. enable_irq() of an interrupt requested with
		 * IRQ_NOAUTOEN is not supposed to fail. The activation
		 * keeps it in shutdown mode, it merily associates
		 * resources if necessary and if that's not possible it
		 * fails. Interrupts which are in managed shutdown mode
		 * will simply ignore that activation request.
		 */
		ret = irq_activate(desc); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_activate().md|irq_activate()]]
		if (ret)
			goto out_unlock;

		desc->istate &= ~(IRQS_AUTODETECT | IRQS_SPURIOUS_DISABLED | \
				  IRQS_ONESHOT | IRQS_WAITING);
		irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

		if (new->flags & IRQF_PERCPU) {
			irqd_set(&desc->irq_data, IRQD_PER_CPU);
			irq_settings_set_per_cpu(desc);
			if (new->flags & IRQF_NO_DEBUG)
				irq_settings_set_no_debug(desc);
		}

		if (noirqdebug)
			irq_settings_set_no_debug(desc);

		if (new->flags & IRQF_ONESHOT)
			desc->istate |= IRQS_ONESHOT;

		/* Exclude IRQ from balancing if requested */
		if (new->flags & IRQF_NOBALANCING) {
			irq_settings_set_no_balancing(desc);
			irqd_set(&desc->irq_data, IRQD_NO_BALANCING); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irqd_set().md|irqd_set()]]
		}

		if (!(new->flags & IRQF_NO_AUTOEN) &&
		    irq_settings_can_autoenable(desc)) {
			irq_startup(desc, IRQ_RESEND, IRQ_START_COND); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_startup().md|irq_startup()]]
		} else {
			/*
			 * Shared interrupts do not go well with disabling
			 * auto enable. The sharing interrupt might request
			 * it while it's still disabled and then wait for
			 * interrupts forever.
			 */
			WARN_ON_ONCE(new->flags & IRQF_SHARED);
			/* Undo nested disables: */
			desc->depth = 1;
		}

	} else if (new->flags & IRQF_TRIGGER_MASK) {
		unsigned int nmsk = new->flags & IRQF_TRIGGER_MASK;
		unsigned int omsk = irqd_get_trigger_type(&desc->irq_data);

		if (nmsk != omsk)
			/* hope the handler works with current  trigger mode */
			pr_warn("irq %d uses trigger mode %u; requested %u\n",
				irq, omsk, nmsk);
	}

	*old_ptr = new;
	//새로운 irq action을 해당하는 irq desc에 넣는 코드

	irq_pm_install_action(desc, new);

	/* Reset broken irq detection when installing new handler */
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;

	/*
	 * Check whether we disabled the irq via the spurious handler
	 * before. Reenable it and give it another chance.
	 */
	if (shared && (desc->istate & IRQS_SPURIOUS_DISABLED)) {
		desc->istate &= ~IRQS_SPURIOUS_DISABLED;
		__enable_irq(desc);
	}

	raw_spin_unlock_irqrestore(&desc->lock, flags);
	chip_bus_sync_unlock(desc);
	mutex_unlock(&desc->request_mutex);

	irq_setup_timings(desc, new);

	wake_up_and_wait_for_irq_thread_ready(desc, new);
	wake_up_and_wait_for_irq_thread_ready(desc, new->secondary);

	register_irq_proc(irq, desc);
	new->dir = NULL;
	register_handler_proc(irq, new);
	return 0;

mismatch:
	if (!(new->flags & IRQF_PROBE_SHARED)) {
		pr_err("Flags mismatch irq %d. %08x (%s) vs. %08x (%s)\n",
		       irq, new->flags, new->name, old->flags, old->name);
#ifdef CONFIG_DEBUG_SHIRQ
		dump_stack();
#endif
	}
	ret = -EBUSY;

out_unlock:
	raw_spin_unlock_irqrestore(&desc->lock, flags);

	if (!desc->action)
		irq_release_resources(desc);
out_bus_unlock:
	chip_bus_sync_unlock(desc);
	mutex_unlock(&desc->request_mutex);

out_thread:
	if (new->thread) {
		struct task_struct *t = new->thread;

		new->thread = NULL;
		kthread_stop_put(t);
	}
	if (new->secondary && new->secondary->thread) {
		struct task_struct *t = new->secondary->thread;

		new->secondary->thread = NULL;
		kthread_stop_put(t);
	}
out_mput:
	module_put(desc->owner);
	return ret;
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-irq/setup_irq_thread().md|setup_irq_thread()]]
[[Encyclopedia of NetworkSystem/Function/kernel-locking/mutex_lock().md|mutex_lock()]]
[[Encyclopedia of NetworkSystem/Function/kernel-irq/chip_bus_lock().md|chip_bus_lock()]]
[[Encyclopedia of NetworkSystem/Function/kernel-irq/__irq_set_trigger().md|__irq_set_trigger()]]
[[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_activate().md|irq_activate()]]
[[Encyclopedia of NetworkSystem/Function/kernel-irq/irqd_set().md|irqd_set()]]
[[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_startup().md|irq_startup()]]

irqaction을 등록하는 내부함수. 주로 아키텍쳐의 일부인 특별한 인터럽트들을 할당하는데 쓰인다.

> handler는 앞서 지정한 interrupt handler, thread_fn은 NULL인 상태임. nested의 뜻은, 인터럽트를 처리하는 중에 또다른 인터럽트를 처리할 수 있는지 유무다. 즉, 계속하여 인터럽트가 겹쳐져서 처리가 될 수 있다는 뜻이다. 그러나 nested가 불가능한 경우 이를 거부할 것이다.

쓰레드화된 인터럽트가 만약 핸들러가 없다면, irq_default_primary_handler나 nested threaded의 경우 irq_nested_primary_handler, irq_forced_secondary_handler를 irq_handler로 직접 할당해주게 된다.

thread_fn이 NULL값으로 전달되었기 때문에, 아래의 과정은 실행되지 않는다. 그러나 software interrupt handler의 핵심 처리과정으로 보여 정리 하였다.

→[[Encyclopedia of NetworkSystem/Function/kernel-irq/setup_irq_thread().md|setup_irq_thread()]] : `*data`로 들어온 irqaction 에 해당하는 irq_handler 함수를 처리하기 위한 커널 쓰레드를 생성하는 함수이다. 해당하는 irq_handler를 실행하는게 아닌 irq_thread()라는 함수를 실행함, 프로세스 이름은 “irq/{irq number}-{irq action의 이름}”으로 지정됨.
	⇒ [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_thread().md|irq_thread()]] (on new kernel thread) : Interrupt handler thread라고 주석 되어 있음. handler_fn 함수 포인터를 선언하여 기다리고 있다가 만약 하드웨어 인터럽트가 끝났다면 irq_thread_fn을 실행함. 이때, irq_thread_fn() 함수는 thread_fn을 실행하게 됨. 여기서부터 software interrupt 처리 과정이 됨.