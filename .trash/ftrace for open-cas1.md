root@white:/sys/kernel/debug/tracing

### **1. ftrace 트레이서 설정**

#### **1) 트레이서 활성화**

`function` 트레이서를 활성화합니다:

```bash
echo function > current_tracer
```
#### **2) Open CAS 관련 함수 필터링**

Open CAS와 관련된 함수 호출만 추적하려면, `set_ftrace_filter`에 특정 함수나 패턴을 추가합니다. 예를 들어, `ocf_*`로 시작하는 모든 함수 호출을 추적하려면:

```bash
echo "*ocf*" > set_ftrace_filter
```
#### **3) 트레이싱 시작**

`tracing_on` 파일을 통해 트레이싱을 활성화합니다:

```bash
echo 1 > tracing_on
```

---
### **2. 로그 확인 및 추출**

#### **1) 실시간 로그 확인**

`trace_pipe` 파일을 통해 실시간으로 로그를 확인할 수 있습니다:

```bash
cat trace_pipe
```
#### **2) 로그 저장**

추적된 로그를 `trace` 파일에서 확인하거나 저장할 수 있습니다:

```bash
cat trace > /path/to/logfile.txt
```

#### **3) 로그 초기화**

```bash
echo > trace
```

---
### **3. 추적 중지**

추적을 중지하려면 `tracing_on` 파일에 `0`을 작성합니다:

```bash
echo 0 > tracing_on
```
---
### **4. 추가 설정**

#### **1) 함수 그래프 추적 활성화**

함수 간의 호출 관계(콜 그래프)를 추적하려면 `function_graph` 트레이서를 활성화합니다:

```bash
echo function_graph > current_tracer
```

#### **2) 함수 호출 시간 활성화**

```bash
echo 1 > options/funcgraph-duration
```

#### **3) 콜스택 깊이 제한**

```bash
echo 5 > max_graph_depth
```

---

