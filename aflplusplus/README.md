# AFLPlusplus
- AFL의 업그레이드 버전. 
- fuzzer 중에서는 문서화가 가장 잘 되어 있음
- 다양한 기능들이 업데이트되고 있음.


## 성능
- oss-fuzz에서 제공하는 랭킹에 따르면, 가장 높은 성능을 보임
![image](https://github.com/JJY-sec/pwnsec-seminar/assets/64367280/c9e4cbe7-e2f1-4959-8e04-037a4edc1e0b)
- 'AFLPlusplus이 최고니까, 무조건 AFLPlusplus 쓰면 됨!'은 아님
  - 다양한 타겟이 있고, 그 타겟에 맞는 전략과 fuzzer를 선택하는 것도 능력

## How to Calculate Coverage?
다음 문단에서 설명할 executor에 따라서 coverage를 측정하는 방법이 달라진다. 가장 기본적인 방식인 compile-time coverage 측정을 기준으로 설명하겠다. 

아래의 코드를 afl-gcc로 컴파일해보자. 
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned int input_number;
    unsigned int compare_number = 0xdeadbeef;

    printf("Please enter a number: ");
    scanf("%x", &input_number);

    if(input_number == compare_number){
        printf("The input number matches with 0xdeadbeef!\n");
    }

    return 0;
}
```
그 결과물을 ida에 넣으면 다음과 같은 결과물이 나온다. 
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  const char *v4; // rdi
  __int64 v5; // rdx
  __int64 v6; // rdx
  __int64 v8; // [rsp+0h] [rbp-B0h]
  __int64 v10; // [rsp+20h] [rbp-90h]
  unsigned int input_number; // [rsp+9Ch] [rbp-14h] BYREF
  unsigned __int64 v12; // [rsp+A0h] [rbp-10h]

  v10 = v3;
  _afl_maybe_log((const char *)argc, argv, envp, 61847LL);
  __endbr64();
  v12 = __readfsqword(0x28u);
  __printf_chk(1LL, "Please enter a number: ", envp, v10);
  v4 = "%x";
  __isoc99_scanf("%x", &input_number);
  if ( input_number == 0xDEADBEEF )
  {
    _afl_maybe_log("%x", &input_number);
    v4 = "The input number matches with 0xdeadbeef!";
    puts("The input number matches with 0xdeadbeef!");
  }
  else
  {
    v8 = v5;
    _afl_maybe_log("%x", &input_number);
    v6 = v8;
  }
  if ( __readfsqword(0x28u) != v12 )
    _afl_maybe_log(v4, &input_number, v6, 7620LL);
  _afl_maybe_log(v4, &input_number, v6, 39590LL);
  return 0;
}
```



## executor 
- dumb
- forkserver
- persistence
- qemu-user
- unicorn
- frida
- nyx

## 추천 타겟 유형



## REF
http://commondatastorage.googleapis.com/fuzzbench-reports/oss-fuzz-benchmarks/index.html
https://aflplus.plus/papers/aflpp-woot2020.pdf
