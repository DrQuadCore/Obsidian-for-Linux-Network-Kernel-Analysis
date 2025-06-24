---
Parameter:
  - napi_struct
Return: bool
Location: /include/linux/netdevice.h
---

```c title=napi_schedule()
static inline bool napi_schedule(struct napi_struct *n)
{
	if (napi_schedule_prep(n)) { // [[Encyclopedia of NetworkSystem/Function/net-core/napi_schedule_prep().md|napi_schedule_prep()]]
		__napi_schedule(n); // [[Encyclopedia of NetworkSystem/Function/net-core/__napi_schedule().md|__napi_schedule()]]
		return true;
	}

	return false;
}
```

[[Encyclopedia of NetworkSystem/Function/net-core/napi_schedule_prep().md|napi_schedule_prep()]]
[[Encyclopedia of NetworkSystem/Function/net-core/__napi_schedule().md|__napi_schedule()]]

위 코드는 네트워크 서브시스템에서 사용되는 NAPI(Network API)의 napi_schedule 함수를 정의하고 있다. 이 함수는 napi_struct 구조체를 스케줄링하여, 네트워크 패킷 처리를 위해 준비된 작업을 큐에 추가하는 역할을 한다.

```c
static inline bool napi_schedule(struct napi_struct *n)
```

- static inline: 이 함수는 정적 인라인 함수로, 컴파일러가 호출하는 대신 함수의 내용을 호출 위치에 삽입하려고 시도한다. 이는 성능을 최적화하기 위해 사용된다.
- bool: 함수는 boolean 값을 반환한다.
- napi_schedule: 함수 이름이다.
- struct napi_struct *n: 함수는 napi_struct 구조체에 대한 포인터 n을 인자로 받는다.

```c
{
	if (napi_schedule_prep(n)) {
```

- if (napi_schedule_prep(n)): napi_schedule_prep 함수는 NAPI 구조체 n이 스케줄링 가능한지 여부를 확인한다. 스케줄링이 가능하면 true를 반환하고, 그렇지 않으면 false를 반환한다.

```c
        __napi_schedule(n);
        return true;
    }
```

- `__napi_schedule(n)`: napi_schedule_prep 함수가 true를 반환하면, `__napi_schedule` 함수를 호출하여 실제로 NAPI 스케줄링을 수행한다. 이는 NAPI 구조체를 활성화하고, 네트워크 패킷 처리를 위한 작업을 큐에 추가한다.
- return true;: NAPI 스케줄링이 성공적으로 수행되었음을 나타내기 위해 true를 반환한다.

```c
    return false;
}
```

- return false;: napi_schedule_prep 함수가 false를 반환하면, 즉 NAPI 스케줄링이 가능하지 않다면 false를 반환한다.

# **요약**
napi_schedule 함수는 napi_struct 구조체가 스케줄링 가능한지 확인하고, 가능하다면 실제 스케줄링을 수행하여 true를 반환한다. 그렇지 않으면 false를 반환한다. 이 함수는 네트워크 인터럽트를 처리하고, 네트워크 패킷 처리를 효율적으로 관리하기 위해 사용된다.