---
Return:
  - gro_result
Location: /net/core/gro.c
parameter:
  - napi_struct
  - sk_buff
---
>만약 합친 `return`이 있다면, *`if(pp)`* ,여기서 `gro_list->count--`를 하는 이유는 그 위에서 `napi_gro_complete()`함수를 실행하면서 해당 `pp`를 네트워크 스택으로 전송하기 때문이다. 따라서 해당 flow는 네트워크 스택으로 올라가게 될 것이므로 더이상 `napi->gro_hash` array에 있지 않기 때문에 이를 위해서 `gro_list->count--`를 하게 되는 것이다.

[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_one()|gro_normal_one()]]