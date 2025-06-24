# fio 명령어

```bash
chanseo@white:~$ sudo fio --name=cas_read_test --filename=/dev/cas1-1 --rw=randread --bs=4k --iodepth=32 --ioengine=libaio --direct=1 --size=1G --runtime=5 --time_based --group_reporting
```

# 반복 패턴 분석
## 1. ocf_cleaner_run 반복
```plaintext
  6)               |  ocf_cleaner_run [cas_cache]() {
  6)               |    ocf_mngt_cache_is_locked [cas_cache]() {
  6)   0.518 us    |      ocf_async_is_locked [cas_cache]();
  6)   1.864 us    |    }
  6)   0.555 us    |    ocf_cache_is_standby [cas_cache]();
  6)               |    ocf_mngt_cache_trylock [cas_cache]() {
  6)   0.521 us    |      ocf_refcnt_inc [cas_cache]();
  6)   0.411 us    |      ocf_async_trylock [cas_cache]();
  6)   2.249 us    |    }
  6)   0.748 us    |    ocf_queue_get [cas_cache]();
  6)   0.401 us    |    ocf_refcnt_inc [cas_cache]();
  6)   0.488 us    |    ocf_realloc_init [cas_cache]();
  6)   0.521 us    |    ocf_realloc [cas_cache]();
  6)               |    ocf_cleaner_run_complete [cas_cache]() {
  6)               |      ocf_mngt_cache_unlock [cas_cache]() {
  6)   0.625 us    |        ocf_async_unlock [cas_cache]();
  6)               |        ocf_mngt_cache_put [cas_cache]() {
  6)   0.388 us    |          ocf_refcnt_dec [cas_cache]();
  6)   1.177 us    |        }
  6)   3.201 us    |      }
  6)   0.428 us    |      ocf_queue_put [cas_cache]();
  6)   0.909 us    |      ocf_cleaner_get_priv [cas_cache]();
  6)   6.428 us    |    }
  6)   0.464 us    |    ocf_refcnt_dec [cas_cache]();
  6) + 22.058 us   |  }
```

```plaintext
 6)               |  ocf_cleaner_run [cas_cache]() {
 6)               |    ocf_mngt_cache_is_locked [cas_cache]() {
 6)   0.518 us    |      ocf_async_is_locked [cas_cache]();
 6)   1.864 us    |    }
 6)   0.555 us    |    ocf_cache_is_standby [cas_cache]();
 6)               |    ocf_mngt_cache_trylock [cas_cache]() {
```

• ocf_cleaner_run이 실행될 때 ocf_mngt_cache_is_locked, ocf_mngt_cache_trylock, ocf_realloc 등의 함수가 반복적으로 실행됨.

• ocf_cleaner_run_complete에서 ocf_mngt_cache_unlock, ocf_queue_put 등의 정리 작업이 반복됨.

• 이 패턴이 **캐시 정리 과정에서 주기적으로 실행**되고 있을 가능성이 큼.

• **캐시 클리너 주기적 실행**으로 반복됨.

• 이는 **캐시 데이터를 정리하는 과정에서 지속적으로 호출됨**.

## 2. ocf_engine_hndl_fast_req 내 ocf_read_fast 반복
```plaintext
 17)               |      ocf_engine_hndl_fast_req [cas_cache]() {
 17)   0.154 us    |        ocf_req_get [cas_cache]();
 17)               |        ocf_read_fast [cas_cache]() {
 17)   0.135 us    |          ocf_req_get [cas_cache]();
 17)               |          ocf_req_hash [cas_cache]() {
 17)   0.148 us    |            ocf_core_get_id [cas_cache]();
 17)   0.454 us    |          }
 17)   0.695 us    |          ocf_hb_req_prot_lock_rd [cas_cache]();
 17)               |          ocf_engine_traverse [cas_cache]() {
 17)               |            ocf_engine_lookup [cas_cache]() {
 17)   0.149 us    |              ocf_core_get_id [cas_cache]();
 17)   0.148 us    |              ocf_req_clear_info [cas_cache]();
 17)               |              ocf_engine_lookup_map_entry [cas_cache]() {
 17)   0.239 us    |                ocf_metadata_get_hash [cas_cache]();
 17)   0.229 us    |                ocf_metadata_get_core_info [cas_cache]();
 17)   0.936 us    |              }
 17)               |              ocf_engine_update_req_info [cas_cache]() {
 17)   0.167 us    |                ocf_metadata_test_valid [cas_cache]();
 17)   0.143 us    |                ocf_metadata_test_dirty [cas_cache]();
 17)   0.237 us    |                ocf_metadata_get_partition_id [cas_cache]();
 17)   1.195 us    |              }
 17)   3.146 us    |            }
 17)   4.545 us    |          }
```

```
17)               |      ocf_engine_hndl_fast_req [cas_cache]() {
17)   0.152 us    |        ocf_req_get [cas_cache]();
17)               |        ocf_read_fast [cas_cache]() {
17)   0.151 us    |          ocf_req_get [cas_cache]();
17)               |          ocf_req_hash [cas_cache]() {
17)   0.143 us    |            ocf_core_get_id [cas_cache]();
17)   0.445 us    |          }
17)   0.250 us    |          ocf_hb_req_prot_lock_rd [cas_cache]();
17)               |          ocf_engine_traverse [cas_cache]() {
```


• ocf_read_fast가 ocf_engine_hndl_fast_req 내부에서 반복 호출됨.

• ocf_engine_lookup 및 ocf_engine_update_req_info와 같은 **캐시 검색 과정**이 반복됨.

• 이 패턴이 **캐시에 HIT/MISS 여부를 판별하는 과정**에서 반복적으로 실행됨.

• **이 패턴은 기존에 발견된 캐시 조회 및 검색 과정의 반복 패턴과 동일함.**

• **OCF Read Fast Path**에서 **HIT/MISS 판단 및 캐시에서 데이터 검색**하는 과정이 반복됨.

## 3. ocf_core_seq_cutoff_update에서 ocf_rb_tree_find 및 ocf_rb_tree_insert 반복
```plaintext
 17)               |      ocf_core_seq_cutoff_update [cas_cache]() {
 17)   0.143 us    |        ocf_core_get_seq_cutoff_policy [cas_cache]();
 17)   0.151 us    |        ocf_core_get_seq_cutoff_threshold [cas_cache]();
 17)   0.152 us    |        ocf_core_get_seq_cutoff_promotion_count [cas_cache]();
 17)   0.152 us    |        ocf_core_get_seq_cutoff_promote_on_threshold [cas_cache]();
 17)               |        ocf_core_seq_cutoff_base_update [cas_cache]() {
 17)               |          ocf_rb_tree_find [cas_cache]() {
 17)   0.159 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.140 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.152 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.142 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   1.420 us    |          }
 17)               |          ocf_rb_tree_remove [cas_cache]() {
 17)   0.160 us    |            ocf_rb_tree_swap [cas_cache]();
 17)   0.147 us    |            ocf_rb_tree_fix_double_black [cas_cache]();
 17)   0.808 us    |          }
 17)               |          ocf_rb_tree_insert [cas_cache]() {
 17)   0.157 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.140 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.151 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   0.151 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
 17)   1.405 us    |          }
 17)   4.234 us    |        }
 17)   5.737 us    |      }
```

• ocf_rb_tree_find, ocf_rb_tree_insert이 반복적으로 실행됨.

• **Red-Black Tree(RB Tree)를 기반으로 한 시퀀스 컷오프 업데이트**가 반복적으로 발생.

• 이는 **데이터를 캐시에 유지할지 여부를 결정하는 정책 수행 과정**으로 보임.

## 4.  ocf_submit_cache_reqs 내 ocf_volume_submit_io 반복

```plaintext
17)               |          ocf_submit_cache_reqs [cas_cache]() {
17)   0.160 us    |            ocf_cache_get_volume [cas_cache]();
17)               |            ocf_volume_new_io [cas_cache]() {
17)               |              ocf_io_new [cas_cache]() {
17)   0.143 us    |                ocf_refcnt_inc [cas_cache]();
17)   0.245 us    |                ocf_io_allocator_default_new [cas_cache]();
17)   0.844 us    |              }
17)   1.145 us    |            }
17)               |            ocf_io_set_data [cas_cache]() {
17)   0.154 us    |              ocf_io_get_priv [cas_cache]();
17)   0.482 us    |            }
17)   0.153 us    |            ocf_core_stats_cache_block_update [cas_cache]();
17)               |            ocf_volume_submit_io [cas_cache]() {
17)   0.139 us    |              ocf_io_get_volume [cas_cache]();
17)   0.139 us    |              ocf_io_get_priv [cas_cache]();
17)   0.151 us    |              ocf_io_get_volume [cas_cache]();
```

• ocf_submit_cache_reqs가 여러 번 실행되면서 ocf_volume_submit_io**가 반복적으로 실행**됨.

• 이는 **캐시 데이터가 백엔드 저장소로 플러시(Flush)되는 과정에서 발생하는 반복 루프**로 보임.

• ocf_io_new -> ocf_io_set_data -> ocf_volume_submit_io 흐름이 계속 반복되며, **IO 요청이 처리되는 패턴을 형성**.

## 5.  ocf_core_seq_cutoff_update 내 ocf_rb_tree_rotate_left 추가 반복
```plaintext
17)               |        ocf_core_seq_cutoff_base_update [cas_cache]() {
17)               |          ocf_rb_tree_find [cas_cache]() {
17)   0.148 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.157 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.141 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.148 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.162 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.137 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   2.316 us    |          }
17)               |          ocf_rb_tree_remove [cas_cache]() {
17)   0.186 us    |            ocf_rb_tree_swap [cas_cache]();
17)   0.521 us    |          }
17)               |          ocf_rb_tree_insert [cas_cache]() {
17)   0.138 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.153 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.157 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.151 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.155 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.147 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.138 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.156 us    |            ocf_rb_tree_rotate_left [cas_cache]();
17)   2.621 us    |          }
```

```plaintext
17)               |          ocf_rb_tree_insert [cas_cache]() {
17)   0.135 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.149 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.149 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.139 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.156 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.152 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.154 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.151 us    |            ocf_rb_tree_rotate_right [cas_cache]();
17)   0.160 us    |            ocf_rb_tree_rotate_left [cas_cache]();
17)   3.045 us    |          }
```

• 기존에 ocf_rb_tree_find**,** ocf_rb_tree_insert**,** ocf_rb_tree_remove**가 반복되던 패턴**에서 추가적으로 ocf_rb_tree_rotate_left**가 등장**.

• 이는 **RB Tree(레드-블랙 트리) 균형 유지 과정**에서 발생하는 반복적인 동작을 나타냄.

• **RB Tree 내부의 균형 조정 과정이 추가된 새로운 패턴으로 확인됨.**

• 기존에는 ocf_rb_tree_rotate_left**만 발견되었으나,** ocf_rb_tree_rotate_right**가 추가로 등장**.

• 이는 **RB 트리의 균형을 조정하는 과정에서 추가적인 우측 회전(Right Rotation)이 발생하고 있음을 의미**.

• 이전에는 ocf_rb_tree_remove에서 ocf_rb_tree_swap과 ocf_rb_tree_fix_double_black가 등장했지만, 이번에는 **추가적인** rotate_right **연산이 들어가면서 트리 균형 조정이 더 많이 발생**.
## 6. ocf_engine_set_hot 내 ocf_metadata_get_lru 다중 반복

```
17)               |            ocf_engine_set_hot [cas_cache]() {
17)               |              ocf_lru_hot_cline [cas_cache]() {
17)   0.175 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_partition_id [cas_cache]();
17)   0.140 us    |                ocf_metadata_test_dirty [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.161 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.160 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.145 us    |                ocf_metadata_get_lru [cas_cache]();
17)   3.528 us    |              }
17)   3.814 us    |            }
```

• ocf_metadata_get_lru가 **여러 번 연속적으로 호출되는 패턴**을 형성함.

• 이는 **LRU(Least Recently Used) 정책을 적용할 때, 캐시의 우선순위를 결정하는 과정에서 발생하는 반복**.

• 특히, **같은** ocf_engine_set_hot **내부에서 연속적인** ocf_metadata_get_lru **호출이 10번 이상 발생**하여 성능 저하를 일으킬 가능성이 있음.

## 7.  ocf_alock_trylock_entry_rd_idle 내부의 ocf_alock_trylock_one_rd 호출 증가

```plaintext
17)               |          ocf_req_async_lock_rd [cas_cache]() {
17)               |            ocf_alock_lock_rd [cas_cache]() {
17)               |              ocf_cl_lock_line_fast [cas_cache]() {
17)   0.147 us    |                ocf_alock_is_index_locked [cas_cache]();
17)               |                ocf_alock_trylock_entry_rd_idle [cas_cache]() {
17)   0.208 us    |                  ocf_alock_trylock_one_rd [cas_cache]();
17)   0.504 us    |                }
17)   0.152 us    |                ocf_alock_mark_index_locked [cas_cache]();
17)   1.385 us    |              }
17)   1.693 us    |            }
17)   1.991 us    |          }
```

• ocf_alock_trylock_entry_rd_idle 내부에서 ocf_alock_trylock_one_rd가 여러 번 호출됨.

• 이는 **캐시 락(lock) 경합이 점점 증가하고 있다는 의미**일 가능성이 큼.

• 이전보다 **락 획득 과정이 더 복잡해지고 있으며, 성능 저하 가능성이 있음**.

## 8. ocf_io_get_priv 및 ocf_io_get_volume 호출 증가
```plaintext
17)   0.149 us    |  ocf_io_get_volume [cas_cache]();
17)   0.154 us    |  ocf_volume_get_priv [cas_cache]();
17)   0.139 us    |  ocf_io_get_priv [cas_cache]();
17)   0.152 us    |  ocf_io_get_priv [cas_cache]();
```

• 입출력(IO) 연산에서 **개별적인** priv **관련 정보를 가져오는 횟수가 증가**.

• ocf_io_get_priv, ocf_io_get_volume, ocf_volume_get_priv 등의 호출이 빈번해지면서 **IO 오버헤드가 누적될 가능성**이 있음.

## 9. ocf_core_seq_cutoff_base_update 내 ocf_seq_cutoff_stream_cmp 호출 증가
```plaintext
17)               |          ocf_rb_tree_find [cas_cache]() {
17)   0.163 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.166 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.158 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.158 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   0.156 us    |            ocf_seq_cutoff_stream_cmp [cas_cache]();
17)   1.757 us    |          }
```

• ocf_seq_cutoff_stream_cmp **호출이 늘어남**.

• 이는 **캐시에서 순차적 접근 여부를 판단하는 과정이 더 많아졌다는 의미**.

• 트래픽이 증가하면서 **캐시 정책이 더 자주 평가되고 있음**.

# Hit vs Miss 실행 경로 분석
지금까지 제공한 ftrace 로그에서 **캐시 히트(hit)** 및 **캐시 미스(miss)** 시 실행되는 코드의 차이를 분석해보았음. ocf_read_fast, ocf_engine_lookup, ocf_engine_update_req_info 등의 함수 호출 패턴을 통해 **히트와 미스의 차이를 추론할 수 있음**.
## 1. 공통적으로 등장하는 실행 흐름
히트와 미스 여부와 관계없이 캐시 조회와 관련된 공통된 함수 흐름은 다음과 같다.
### (1) 캐시 요청이 발생하면 ocf_engine_hndl_fast_req에서 시작
```plaintext
17)               |      ocf_engine_hndl_fast_req [cas_cache]() {
17)   0.155 us    |        ocf_req_get [cas_cache]();
17)               |        ocf_read_fast [cas_cache]() {
```

• 요청이 들어오면 **ocf_engine_hndl_fast_req**가 호출됨.

• 이후 **캐시 읽기(**ocf_read_fast**)** 작업으로 이어짐.
### (2) 캐시 조회 실행
```plaintext
17)               |          ocf_req_hash [cas_cache]() {
17)   0.151 us    |            ocf_core_get_id [cas_cache]();
17)   0.471 us    |          }
```

• ocf_req_hash가 실행되어 **캐시에 해당 요청이 있는지 확인**함.

## 2. 캐시 Hit 실행 코드
캐시 히트 시에는 다음과 같은 실행 흐름이 보임.
### (1) ocf_engine_lookup_map_entry 실행
```plaintext
17)               |              ocf_engine_lookup_map_entry [cas_cache]() {
17)   0.259 us    |                ocf_metadata_get_hash [cas_cache]();
17)   0.267 us    |                ocf_metadata_get_core_info [cas_cache]();
17)   0.979 us    |              }
```

• ocf_engine_lookup_map_entry에서 **캐시 메타데이터(hash, core info) 조회**가 이루어짐.

• 여기서 유효한 데이터가 발견되면 캐시 히트임.
### (2) 캐시 상태 업데이트 및 캐시 데이터 읽기
```plaintext
17)               |              ocf_engine_update_req_info [cas_cache]() {
17)   0.168 us    |                ocf_metadata_test_valid [cas_cache]();
17)   0.143 us    |                ocf_metadata_test_dirty [cas_cache]();
17)   0.236 us    |                ocf_metadata_get_partition_id [cas_cache]();
17)   1.190 us    |              }
```

• ocf_metadata_test_valid와 ocf_metadata_test_dirty가 실행됨.

• 이는 캐시에 데이터가 존재하고, 해당 데이터가 최신인지 확인하는 과정.

• 이후 ocf_metadata_get_partition_id**를 통해 캐시 블록을 찾아서 데이터를 반환**함.
### (3) ocf_engine_set_hot 실행 (LRU 업데이트)
```plaintext
17)               |            ocf_engine_set_hot [cas_cache]() {
17)               |              ocf_lru_hot_cline [cas_cache]() {
17)   0.162 us    |                ocf_metadata_get_lru [cas_cache]();
17)   0.531 us    |              }
17)   0.831 us    |            }
```

• 캐시에서 **가져온 블록을 LRU 리스트의 상위로 이동**시킴.

• 이 과정이 실행되는 경우 **캐시 히트일 가능성이 높음**.

## 3. 캐시 Miss 실행 코드
캐시 미스가 발생했을 때는 캐시 히트 코드와 다른 흐름을 보임.
### (1) ocf_engine_lookup_map_entry에서 데이터 없음 감지
```plaintext
17)               |              ocf_engine_lookup_map_entry [cas_cache]() {
17)   0.259 us    |                ocf_metadata_get_hash [cas_cache]();
17)   0.267 us    |                ocf_metadata_get_core_info [cas_cache]();
17)   0.979 us    |              }
```

• 캐시 히트와 동일한 과정으로 보이지만, **이후** ocf_engine_update_req_info**가 실행되지 않음**.

• 즉, ocf_metadata_test_valid가 호출되지 않았거나 빠르게 종료되었을 가능성이 높음.

• 이는 **캐시에 해당 블록이 존재하지 않음을 의미**.
### (2) 캐시 블록 할당 요청 (ocf_req_alloc_map)
```plaintext
17)   0.140 us    |      ocf_req_alloc_map [cas_cache]();
```

• 캐시에 없는 데이터이므로 **새로운 캐시 블록을 할당하려는 시도**가 이루어짐.
### (3) ocf_resolve_effective_cache_mode에서 캐시 쓰기 정책 확인
```plaintext
17)               |      ocf_resolve_effective_cache_mode [cas_cache]() {
17)               |        ocf_core_seq_cutoff_check [cas_cache]() {
17)   0.141 us    |          ocf_core_get_seq_cutoff_policy [cas_cache]();
17)   0.154 us    |          ocf_core_get_seq_cutoff_threshold [cas_cache]();
```

• 캐시에 없는 데이터이므로 **읽기 정책(**ocf_core_seq_cutoff_check**)을 확인함**.

• 순차적인 접근 패턴이면 캐싱하지 않거나 특정 정책을 적용할 수도 있음.
### (4) 캐시 미스 핸들링 (ocf_submit_cache_reqs)
```plaintext
17)               |          ocf_submit_cache_reqs [cas_cache]() {
17)   0.138 us    |            ocf_cache_get_volume [cas_cache]();
17)               |            ocf_volume_new_io [cas_cache]() {
```

• 캐시에서 데이터가 없으므로 **디스크에서 데이터를 가져오는 요청을 생성**함.
### (5) 새로운 캐시 블록 생성 및 추가 (ocf_volume_submit_io)
```plaintext
17)               |            ocf_volume_submit_io [cas_cache]() {
17)   0.150 us    |              ocf_io_get_volume [cas_cache]();
17)   0.151 us    |              ocf_io_get_priv [cas_cache]();
17)   0.146 us    |              ocf_io_get_volume [cas_cache]();
17)   0.137 us    |              ocf_volume_get_priv [cas_cache]();
```

• 새로운 블록을 생성하고 **디스크에서 데이터를 가져와 캐시에 저장**함.
## 4. Hit vs Miss 차이점 정리 
| <p class="p1" style="margin: 0px; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;; color: rgb(14, 14, 14);"><b>구분</b></p> | <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">캐시 Hit</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">캐시 Miss</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">캐시 조회</span>                                                                                                                                                                                                                                                  | <p class="p1" style="margin: 0px; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFontMonospaced&quot;; color: rgb(14, 14, 14);">ocf_engine_lookup_map_entry<span class="s1" style="font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;"> → </span>ocf_metadata_get_hash<span class="s1" style="font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;"> → </span>ocf_metadata_get_core_info</p> | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_engine_lookup_map_entry</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;실행 후 빠르게 종료</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">데이터 유효성 검사</span>                                                                                                                                                                                                                                             | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_metadata_test_valid</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;→&nbsp;</span><span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_metadata_test_dirty</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">실행되지 않음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">LRU 업데이트</span>                                                                                                                                                                                                                                               | <p class="p1" style="margin: 0px; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFontMonospaced&quot;; color: rgb(14, 14, 14);">ocf_engine_set_hot<span class="s1" style="font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;"> 실행</span></p>                                                                                                                                                                                                                                                                                                                                                                                                                                  | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">실행되지 않음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">캐시 블록 할당</span>                                                                                                                                                                                                                                               | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">없음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | <span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">(기존 데이터 사용)</span><span class="s1" style="font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 12px; line-height: normal; font-family: Helvetica; color: rgb(0, 0, 0);"><span class="Apple-tab-span" style="white-space: pre;">	</span></span><span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_req_alloc_map</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;실행</span> |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">캐시 정책 확인</span>                                                                                                                                                                                                                                               | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">없음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_resolve_effective_cache_mode</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;실행</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">디스크 읽기 요청</span>                                                                                                                                                                                                                                              | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">없음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_submit_cache_reqs</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;실행</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| <span style="font-weight: calc(var(--font-weight) + var(--bold-modifier)); color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">새로운 캐시 블록 생성</span>                                                                                                                                                                                                                                           | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFont&quot;; font-size: 11px;">없음</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | <span style="color: rgb(14, 14, 14); font-family: &quot;.AppleSystemUIFontMonospaced&quot;; font-size: 11px;">ocf_volume_submit_io</span><span class="s2" style="color: rgb(14, 14, 14); font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; font-variation-settings: normal; font-variant-position: normal; font-stretch: normal; font-size: 11px; line-height: normal; font-family: &quot;.AppleSystemUIFont&quot;;">&nbsp;실행</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

# 캐시 Hit 시 캐시 장치(Cache Device)와 코어 장치(Core Device) 간에 static split 조정 Hypothesis
캐시 히트 시 실행되는 코드에서, **캐시에서 데이터를 읽어오는 부분과 코어 장치로 전달하는 부분을 조정하면 원하는 목표(80:20) 비율을 적용할 수 있음**. 이를 위해 주요 함수들을 정리해보았음.
## 1. 수정해야 할 주요 함수들
### (1) ocf_read_fast() - 캐시 히트 시 실행되는 핵심 함수
```plaintext
17)               |        ocf_read_fast [cas_cache]() {
17)   0.151 us    |          ocf_req_get [cas_cache]();
17)               |          ocf_req_hash [cas_cache]() {
17)   0.151 us    |            ocf_core_get_id [cas_cache]();
17)   0.471 us    |          }
```

• **역할**: 캐시를 빠르게 읽어와서 데이터를 반환하는 역할.

• **변경해야 할 부분**: ocf_read_fast() 내부에서 **일을 캐시 장치(Cache Device)와 코어 장치(Core Device)로 나누어 처리하는 로직 추가**.

📌 **수정 방법**

• 현재는 캐시 히트 시 ocf_read_fast()가 **100% 캐시에서 데이터를 제공**하지만, **20%의 데이터를 코어 장치에서 가져오도록 비율 조정**해야 함.

• ocf_read_fast() 내에서 **80:20 비율을 결정하는 로직을 추가하고, 일부 데이터를** ocf_submit_cache_reqs()**를 통해 코어 장치에서 가져오도록 수정**.
### (2) ocf_engine_lookup_map_entry() - 캐시 블록 조회
```plaintext
17)               |              ocf_engine_lookup_map_entry [cas_cache]() {
17)   0.259 us    |                ocf_metadata_get_hash [cas_cache]();
17)   0.267 us    |                ocf_metadata_get_core_info [cas_cache]();
17)   0.979 us    |              }
```

• **역할**: 캐시에서 특정 블록이 존재하는지 확인하는 역할.

• **변경해야 할 부분**: 블록이 히트했을 때, **80%는 캐시에서, 20%는 코어에서 데이터를 가져오도록 변경**.

📌 **수정 방법**

• ocf_engine_lookup_map_entry()에서 **히트된 블록을 조회한 후, 일정 확률(20%)로 코어에서 데이터를 가져오도록 분기 추가**.

• 이를 위해 **확률 기반(random) 또는 특정 조건을 기준으로 분기 처리 가능**.
### (3) ocf_submit_cache_reqs() - 코어 장치에서 데이터 가져오는 함수
```plaintext
17)               |          ocf_submit_cache_reqs [cas_cache]() {
17)   0.138 us    |            ocf_cache_get_volume [cas_cache]();
17)               |            ocf_volume_new_io [cas_cache]() {
17)               |              ocf_io_new [cas_cache]() {
17)   0.151 us    |                ocf_refcnt_inc [cas_cache]();
17)   0.236 us    |                ocf_io_allocator_default_new [cas_cache]();
17)   0.824 us    |              }
```

• **역할**: **캐시에 없는 데이터를 코어 장치에서 가져오는 역할 (미스 시 실행됨)**.

• **변경해야 할 부분**: 캐시 히트가 발생하더라도 **일부 요청을 코어에서 가져오도록 유도**.

📌 **수정 방법**

• ocf_submit_cache_reqs()를 **강제로 20%의 확률로 실행**하게 만들어서, 일부 데이터를 코어 장치에서 처리하도록 함.

• ocf_engine_lookup_map_entry()에서 **20%의 경우** ocf_submit_cache_reqs()**를 실행하도록 수정**.
## 2. 수정할 핵심 코드 흐름
위 내용을 기반으로 코드 수정 방향을 정리하면 다음과 같다.
### 1) ocf_read_fast() 내부에서 80:20 비율 적용

```c
if (cache_hit) {
    int random_val = rand() % 100; // 0~99 사이의 랜덤 값 생성

    if (random_val < 80) {
        // 80% 확률로 기존 방식 그대로 캐시에서 읽음
        ocf_engine_hndl_fast_req(cache);
    } else {
        // 20% 확률로 캐시를 무시하고 코어 장치에서 읽음
        ocf_submit_cache_reqs(core);
    }
}
```

**💡 이 코드의 역할**

• rand() % 100을 사용해서 80%는 기존 방식대로 캐시에서 데이터 가져오기.

• 20%의 확률로 **캐시를 무시하고 코어에서 데이터를 가져오도록** ocf_submit_cache_reqs() **실행**.
### 2) ocf_engine_lookup_map_entry() 수정하여 80:20 조정
```c
if (cache_hit) {
    if (random_val < 80) {
        // 80%: 캐시에서 처리
        ocf_metadata_get_hash();
        ocf_metadata_get_core_info();
    } else {
        // 20%: 코어에서 처리
        ocf_submit_cache_reqs(core);
    }
}
```

**💡 이 코드의 역할**

• 기존에는 무조건 캐시에서 데이터를 가져왔지만, **20% 확률로** ocf_submit_cache_reqs()**를 호출하여 코어 장치에서 읽음**.
### 3) ocf_submit_cache_reqs()에서 캐시 데이터를 일부 무시하고 코어에서 읽도록 수정
```c
void ocf_submit_cache_reqs(struct ocf_request *req) {
    if (req->data_source == CACHE) {
        if (random_val < 80) {
            // 80% 확률로 캐시에서 읽기
            ocf_cache_get_volume();
        } else {
            // 20% 확률로 강제적으로 코어에서 읽기
            ocf_core_volume_submit_io();
        }
    }
}
```

**💡 이 코드의 역할**

• 캐시 데이터를 가져오는 비율을 80:20으로 조정.

• 일부 데이터를 **강제로 코어에서 읽어와서 코어 장치에 부하를 주도록 설계**.
## 3. 요약

1. **캐시 히트 시에도 일부 데이터를 코어에서 가져오도록 수정해야 함.**

2. ocf_read_fast() 내부에서 **80:20 확률로 캐시 vs 코어 데이터를 가져오는 로직 추가**.

3. ocf_engine_lookup_map_entry()에서 **확률 기반으로 코어 데이터 조회 요청**.

4. ocf_submit_cache_reqs()를 **캐시 히트에도 일부 실행되도록 수정**.
