## Userspace
### glibc 동작(send, sendto)
- glibc의 코드는 아키텍쳐마다 차이가 있으며 x86_64를 기준으로 작성하였다.
- 유저 스페이스에서 시스템 콜을 호출할때는 glibc라는 인터페이스를 거쳐서 커널 스페이스의 동작을 수행한다. 전체적으로 래퍼 함수 역할을 수행한다.
  
- send(), sendto() 같이 유저스페이스에서 호출되는 함수들 또한 glibc에 정의되어 있으며 이를 통해 시스템 콜이 실행된다.

```c title=__libc_send()
ssize_t
__libc_send (int fd, const void *buf, size_t len, int flags)
{
	/* x86_64 에서는 __ASSUME_SEND_SYSCALL가 정의되어 있지 않다. 
	따라서 sendto와 동일한 경로로 시스템콜이 동작한다.
	*/
	
#ifdef __ASSUME_SEND_SYSCALL
  return SYSCALL_CANCEL (send, fd, buf, len, flags);
#elif defined __ASSUME_SENDTO_SYSCALL
  return SYSCALL_CANCEL (sendto, fd, buf, len, flags, NULL, 0);
#else
  return SOCKETCALL_CANCEL (send, fd, buf, len, flags);
#endif
}
weak_alias (__libc_send, send)
weak_alias (__libc_send, __send)
libc_hidden_def (__send)
```

``` c title=__libc_sendto()
ssize_t
__libc_sendto (int fd, const void *buf, size_t len, int flags,
               __CONST_SOCKADDR_ARG addr, socklen_t addrlen)
{
#ifdef __ASSUME_SENDTO_SYSCALL
  return SYSCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
                         addrlen);
#else
  return SOCKETCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
                            addrlen);
#endif
}
weak_alias (__libc_sendto, sendto)
weak_alias (__libc_sendto, __sendto)
```

- 각각은 glibc/sysdeps/unix/sysv/linux/send.c 및 glibc/sysdeps/unix/sysv/linux/sendto.c에 구현되어 있다.
- weak_alias()로 send 혹은 sendto를 호출하면 \_\_libc_sendto, \_\_libc_send 가 호출된다.
- 실제로 시스템콜 동작을 하기 위해서는 SYSCALL_CANCEL 매크로 함수가 수행된다.
  아래의 매크로 함수들이 래퍼 함수의 역할들을 수행한다.

```c
# define SYSCALL_CANCEL(...)          INLINE_SYSCALL_CALL (__VA_ARGS__)
```

```
#define INLINE_SYSCALL_CALL(...) \
  __INLINE_SYSCALL_DISP (__INLINE_SYSCALL, __VA_ARGS__)

#define __INLINE_SYSCALL_DISP(b,...) \
  __SYSCALL_CONCAT (b,__INLINE_SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)
```
- \_\_INLINE_SYSCALL_DISP() 함수의 인자로 \_\_INLINE_SYSCALL 이라는 값이 들어간다(위의 함수에서 b에 해당함). 

```c
#define __INLINE_SYSCALL_NARGS(...) \
  __INLINE_SYSCALL_NARGS_X (__VA_ARGS__,7,6,5,4,3,2,1,0,)
  
// arguments의 개수를 반환하는 매크로 함수
#define __INLINE_SYSCALL_NARGS_X(a,b,c,d,e,f,g,h,n,...) n  
```
- 이 매크로 함수는 인자의 개수를 반환한다. sendto의 경우 6개의 인자가 있으므로 6을 반환한다.

```c
#define __SYSCALL_CONCAT(a,b)       __SYSCALL_CONCAT_X (a, b)

// a, b를 이어주는 매크로 함수
#define __SYSCALL_CONCAT_X(a,b)     a##b  
```
- 매크로 함수에서 ## 연산자는 인자들을 이어주는 역할을 수행한다.

```
#define INLINE_SYSCALL_CALL(...) \
  __INLINE_SYSCALL_DISP (__INLINE_SYSCALL, __VA_ARGS__)

#define __INLINE_SYSCALL_DISP(b,...) \
  __SYSCALL_CONCAT (b,__INLINE_SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)
  
// --> __INLINE_SYSCALL + 인자개수() 라는 함수가 호출되는 구조
```
- \_\_SYSCALL_CONCAT 매크로 함수를 통해서 \_\_INLINE_SYSCALL와 arguments 개수를 이어준다. 
  결과적으로 인자가6개인 sendto는 \_\_INLINE_SYSCALL6이 호출되는 구조이다.

```c
#define __INLINE_SYSCALL6(name, a1, a2, a3, a4, a5, a6) \
  INLINE_SYSCALL (name, 6, a1, a2, a3, a4, a5, a6)
```
- 인자의 개수만 달라질 뿐 동일한 매크로 함수인 INLINE_SYSCALL 이 호출된다.

```c
#define INLINE_SYSCALL(name, nr, args...)				\
  ({									\
    long int sc_ret = INTERNAL_SYSCALL (name, nr, args);		\
    __glibc_unlikely (INTERNAL_SYSCALL_ERROR_P (sc_ret))		\
    ? SYSCALL_ERROR_LABEL (INTERNAL_SYSCALL_ERRNO (sc_ret))		\
    : sc_ret;								\
  })
```
- 이어서 INTERNAL_SYSCALL() 매크로 함수를 호출한다. 

```
  #define INTERNAL_SYSCALL(name, nr, args...)				\
	internal_syscall##nr (SYS_ify (name), args)
```
- INTERNAL_SYSCALL() 매크로 함수 또한 arguments 개수를 internal_syscall 뒤에 이어붙여서 호출하도록 한다.

```
#define SYS_ify(syscall_name)	__NR_##syscall_name
```
- SYS_ify 매크로 함수는 시스템콜 이름을 시스템콜 번호로 바꿔주는 역할을 한다. 
  (ex: \_\_NR_sendto) 
-  \_\_NR_시스템콜이름 은 매크로 상수 형태로 시스템콜 번호를 나타낸다.

- 시스템콜 번호가 정의된 시스템콜 테이블은  
  `커널 디렉토리/arch/x86/entry/syscalls/syscall_64.tbl` 에 있으며 
  시스템콜 번호, ABI(64, x32, common), 이름, 엔트리 포인트 순서로 작성돼있다.
- 앞서 x86_64 에서는 send대신 sendto를 사용한다는 것을 확인했다. 시스템콜 테이블에서도 send는 없는 걸 확인할 수 있다.
```c title=syscall_64.tbl
...
44      common  sendto                  sys_sendto
45      64      recvfrom                sys_recvfrom
46      64      sendmsg                 sys_sendmsg
47      64      recvmsg                 sys_recvmsg
...
```

   `커널 디렉토리/arch/x86/include/generated/uapi/asm/unistd_64.h`에 시스템콜 테이블에 정의된 시스템 콜의 번호가 매크로로 정의되어 있다. 아래를 보면 sendto는 44번으로 정의된 것을 확인할 수 있다.
```c title=unistd_64.h
...
#define __NR_connect 42
#define __NR_accept 43
#define __NR_sendto 44 //sendto의 시스템콜 번호가 44임을 매크로 상수로 정의한다.
...
```
  - sendto의 경우 \_\_NR_sendto가 되며시스템콜 번호가 44이므로 internal_syscall6(44, args)가 호출되는 것이다.

```c
#define internal_syscall6(number, arg1, arg2, arg3, arg4, arg5, arg6) \
({									\
    unsigned long int resultvar;					\
    TYPEFY (arg6, __arg6) = ARGIFY (arg6);			 	\
    TYPEFY (arg5, __arg5) = ARGIFY (arg5);			 	\
    TYPEFY (arg4, __arg4) = ARGIFY (arg4);			 	\
    TYPEFY (arg3, __arg3) = ARGIFY (arg3);			 	\
    TYPEFY (arg2, __arg2) = ARGIFY (arg2);			 	\
    TYPEFY (arg1, __arg1) = ARGIFY (arg1);			 	\
    register TYPEFY (arg6, _a6) asm ("r9") = __arg6;			\
    register TYPEFY (arg5, _a5) asm ("r8") = __arg5;			\
    register TYPEFY (arg4, _a4) asm ("r10") = __arg4;			\
    register TYPEFY (arg3, _a3) asm ("rdx") = __arg3;			\
    register TYPEFY (arg2, _a2) asm ("rsi") = __arg2;			\
    register TYPEFY (arg1, _a1) asm ("rdi") = __arg1;			\
    asm volatile (							\
    "syscall\n\t"							\
    : "=a" (resultvar)							\
    : "0" (number), "r" (_a1), "r" (_a2), "r" (_a3), "r" (_a4),		\
      "r" (_a5), "r" (_a6)						\
    : "memory", REGISTERS_CLOBBERED_BY_SYSCALL);			\
    (long int) resultvar;						\
})
```
- 인자들을 레지스터에 저장한다. 
- asm으로 쓸 수 있는 인라인 어셈블리는 c언어로 어셈블리 명령어를 작성할 수 있게 해준다. 
  asm vilatile() 의 경우 괄호 안의 명령어를 컴파일러가 최적화하지 않고 코드가 작성된 순서 그대로 실행하라는 의미이다. 
  
-  internal_syscall6() 함수 내부에서는 인자들을 레지스터에 넣어주고 syscall이라는 어셈블리 명령어가 실행된다. 
  
- syscall 명령어는 유저 스페이스에서 커널 스페이스로 넘어가도록 하는 x86_64 아키텍처의 명령어이다. 이 명령어에서는 MSR_LSTAR 레지스터에 있는 주소를 이용해 커널 스페이스의 엔트리 포인트로 들어간다. 
  MSR_LSTAR 레지스터에 어느 명령어의 주소가 저장되어 있는지는  커널 초기화 단계에서 설정된다.

```c
void syscall_init(void)
{
	/* The default user and kernel segments */
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);

	if (!cpu_feature_enabled(X86_FEATURE_FRED))
		idt_syscall_init();
}

static inline void idt_syscall_init(void)
{
	//LSTAR 레지스터에 저장할 주소값 --> entry_SYSCALL_64 심볼의 주소
	wrmsrq(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);

	if (ia32_enabled()) {
		wrmsrq_cstar((unsigned long)entry_SYSCALL_compat);
	...
}
```
- cpu_init() -> syscall_init() -> idt_syscall_init() 함수에서 LSTAR 레지스터에 저장할 주소가  entry_SYSCALL_64 라는 것을 확인할 수 있다. entry_SYSCALL_64라는 심볼의 주소는 심볼테이블에 작성돼 있다.
```c title=System.map
...
// 컴파일러가 이 심볼 테이블을 참조한다.
// 주소가 ffffffff81000080 임을 확인할 수 있다. (T는 코드 안에 정의된 전역 심볼이라는 의미)
ffffffff81000080 T entry_SYSCALL_64   
ffffffff810000a7 T entry_SYSCALL_64_safe_stack
...
```
## Kernel space

```c
//전역코드심볼로 정의(다른 어셈블리 파일 또는 c 파일에서 호출 가능)
SYM_CODE_START(entry_SYSCALL_64)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_safe_stack, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	movq	%rsp, %rdi
	/* Sign extend the lower 32bit as syscall numbers are treated as int */
	movslq	%eax, %rsi

	/* clobbers %rax, make sure it is after saving the syscall nr */
	IBRS_ENTER
	UNTRAIN_RET
	CLEAR_BRANCH_HISTORY

	call	do_syscall_64		/* returns with IRQs disabled */

	...
```
- entry_SYSCALL_64 라는 심볼을 다른 파일에서 호출할 수 있도록 정의되어 있다. 
- 최종적으로 do_syscall_64() 함수를 호출한다.

```c
__visible noinstr bool do_syscall_64(struct pt_regs *regs, int nr)
{
	add_random_kstack_offset();
	nr = syscall_enter_from_user_mode(regs, nr);

	instrumentation_begin();

	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
		/* Invalid system call, but still a system call. */
		regs->ax = __x64_sys_ni_syscall(regs);
	}

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
	
	/* XEN PV guests always use the IRET path */
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return false;

	/* SYSRET requires RCX == RIP and R11 == EFLAGS */
	if (unlikely(regs->cx != regs->ip || regs->r11 != regs->flags))
		return false;

	/* CS and SS must match the values set in MSR_STAR */
	if (unlikely(regs->cs != __USER_CS || regs->ss != __USER_DS))
		return false;


	if (unlikely(regs->ip >= TASK_SIZE_MAX))
		return false;

	if (unlikely(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)))
		return false;

	/* Use SYSRET to exit to userspace */
	return true;
}
```

```c
static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
{
	/* nr을 unsigned int로 바꿔서 음수인 경우 2의 보수 때문에 매우 큰 값이 나온다*/
	unsigned int unr = nr;
	
	// 시스템콜의 최대 개수인 NR_syscalls보다 작은 경우 x64_sys_call() 호출
	if (likely(unr < NR_syscalls)) {
		// unr이 NR_syscalls 이내의 값이 되도록 설정(안전장치 역할)
		unr = array_index_nospec(unr, NR_syscalls);
		regs->ax = x64_sys_call(regs, unr);
		return true;
	}
	return false;
}
```

```c
long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
}
```
- 시스템콜 번호를 통해 switch-case 문으로 들어간다. case 의 코드는 syscalls_64.h 헤더파일에 구현돼있다.

```c title=arch/x86/include/generated/asm/syscalls_64.h
...
__SYSCALL(44, sys_sendto)
__SYSCALL(45, sys_recvfrom)
__SYSCALL(46, sys_sendmsg)
...
```
- syscalls_64.h 헤더파일은 커널 컴파일 시 생성되며 내부에는 \_\_SYSCALL() 매크로 함수들이 나열돼있다.

```c
#define __SYSCALL(nr, sym) case nr: return __x64_##sym(regs);
```
- 결국 시스템콜 번호를 switch-case문을 통해 \_\_x64_sys_시스템콜 이름() 이 호출되며 
  sendto의 경우 \_\_x64_sys_sendto() 가 호출된다. 

---

- \_\_x64_sys_sendto() 같은 함수는 SYSCALL_DEFINE6 형태의 매크로 함수 안에 정의되어있다. 
- 이어서 호출되는 함수들은 함수명이 정해져있는 구조가 아닌 ## 으로 이름이 연결된 형태의 함수로 구성돼 있다. 따라서 함수 정의의 시작지점인 SYSCALL_DEFINE6() 함수 순서대로 설명할 것이다.

```c title=SYSCALL_DEFINE6()
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
```

- 시스템콜 이름 맨앞에 _ 를 붙이고 SYSCALL_DEFINEx() 을 호출한다. sendto라면 `_sendto` 
  를 name 인자로 함수가 호출된다.

```c title=SYSCALL_DEFINEx()
#define __SYSCALL_DEFINEx(x, name, ...)					\
	//나중에 호출할 함수 선언
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	
	//__x64_sys_sendto() 같은 형태의 함수를 정의하기 위한 매크로 함수 호출
	__X64_SYS_STUBx(x, name, __VA_ARGS__)				\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

```
-  SYSCALL_DEFINEx() 매크로 함수 내부에서 함수들을 선언하고 \_\_X64_SYS_STUBx() 함수를 호출한다. 

```c
#define __X64_SYS_STUBx(x, name, ...)					\
	//sys와 _시스템콜 이름을 이어붙인 것으로 함수를 호출한다. (ex: sys_sendto)
	__SYS_STUBx(x64, sys##name,					\
		    SC_X86_64_REGS_TO_ARGS(x, __VA_ARGS__))
		    

#define __SYS_STUBx(abi, name, ...)					\
	/*인자로 받은 abi(x64)와 sys_시스템콜 이름을 이어붙인 함수를 정의한다.
	즉, 이전에 switch-case 문에서 호출한 __x64_sys_sendto() 함수가 정의된 부분.
	*/
	long __##abi##_##name(const struct pt_regs *regs);		\
	ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);			\
	long __##abi##_##name(const struct pt_regs *regs)		\
	{								\
		return __se_##name(__VA_ARGS__);			\
	}

```
- 이어서 \_\_SYS_STUBx() 함수를 호출한다. 이때 sys와 시스템콜 이름을 이어붙인 것을 인자로 함수를 호출하게 된다. sendto의 경우 sys_sendto 가 된다.

- \_\_SYS_STUBx() 함수 내부에서 \_\_abi와 sys_시스템콜 이름이 이어붙여진 형태로 함수가 정의된다. 현재 abi가 x64이고 시스템콜 이름이 sendto라고 가정하면 이전에 스위치 케이스 문에서 호출한 \_\_x64_sys_sendto() 함수가 정의된 부분인 것이다. 이 함수에서는 \_\_se_sys_sendto() 라는 함수가 호출된다.

-  \_\_se_sys_sendto() 함수는 앞서 \_\_SYSCALL_DEFINEx() 매크로 함수 안에 정의돼있다. 

```c title=SYSCALL_DEFINEx()
#define __SYSCALL_DEFINEx(x, name, ...)					\
	//나중에 호출할 함수 선언
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	
	//__x64_sys_sendto() 같은 형태의 함수를 정의하기 위한 매크로 함수 호출
	__X64_SYS_STUBx(x, name, __VA_ARGS__)				\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	
	// se_sys_sendto() 함수가 정의된 부분
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	
	// __do_sys_sendto() 함수를 정의하기 위한 부분. socket.c에 함수 내용이 있다.
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
```
-  \_\_se_sys_sendto() 함수는 \_\_do_sys_sendto() 함수를 호출하도록 한다. 
  
- \_\_do_sys_sendto()  함수 자체는 매크로 함수 안에 정의되어 있지 않고 SYSCALL_DEFINE6() 라는 매크로 함수를 따로 호출해서 그 내용을 정의한다.
  
- send와 sendto는 `커널 디렉토리/net/socket.c` 안에서 각각 SYSCALL_DEFINE4(), SYSCALL_DEFINE6() 를 호출한다. 

```c 
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	return __sys_sendto(fd, buff, len, flags, NULL, 0);
}
```

```c
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr,
		int, addr_len)
{
	return __sys_sendto(fd, buff, len, flags, addr, addr_len);
}
```

- 전처리 단계에서 \_\_SYSCALL_DEFINEx() 매크로 함수와 연결되면서 \_\_do_sys_sendto() 함수의 내용이 아래의 \_\_sys_sendto() 함수를 호출하도록 정의되는 구조이다.

[[함수 콜 스택(TX)]] 좌측 시스템콜 부분 참고

---

[[__sys_sendto()]]
