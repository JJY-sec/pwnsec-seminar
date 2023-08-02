# AFLPlusplus
- masterpiece fuzzer인 AFL의 업그레이드 버전. 
- fuzzer 중에서는 문서화가 가장 잘 되어 있음
- 다양한 기능들이 업데이트되고 있음.


## 성능
- oss-fuzz에서 제공하는 랭킹에 따르면, 가장 높은 성능을 보임
![image](https://github.com/JJY-sec/pwnsec-seminar/assets/64367280/c9e4cbe7-e2f1-4959-8e04-037a4edc1e0b)
- 'AFLPlusplus이 최고니까, 무조건 AFLPlusplus 쓰면 됨!'은 아님
  - 세상에는 다양한 타겟이 있고, 그 타겟에 맞는 전략과 fuzzer를 선택하는 것도 능력

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

코드의 분기가 나뉠 때마다 _afl_maybe_log 함수가 호출되는 것을 볼 수 있다.
이제 _afl_maybe_log 함수를 분석해보자. AFLPlusplus 코드를 보면 해당 함수는 어셈블리로 짜였다. 
- https://github.com/AFLplusplus/AFLplusplus/blob/stable/include/afl-as.h#L166

IDA로 보면 결과물이 상당히 지저분하기 때문에, 필요한 부분만 발췌했다. 
- [1] 환경변수에서 __AFL_SHM_ID라는 값을 가져온다. 이 값은 fuzzer와 target process가 공유하는 환경변수이다.
- [2] __AFL_SHM_ID를 이용하여 공유 메모리를 할당한다. 이를 통해 fuzzer와 공유 메모리를 함께 소유할 수 있다.
- [3] \_afl_prev_loc과 unique_value를 xor한다. 이 값을 cur_value라고 지칭한다.
  - unique_value는 _afl_maybe_log의 인자이다. 각 block마다 다른 값을 가지며, 컴파일 타임에 랜덤한 값이 들어간다.
- [5]  cur_value에 해당하는 idx에 shared memory의 값을 1증가한다.

```c
char __fastcall _afl_maybe_log(const char *a1, __int64 a2, __int64 a3, __int64 unique_value)
{
...

      __AFL_SHM_ID = getenv("__AFL_SHM_ID");//[1]
      if ( !__AFL_SHM_ID
        || (__AFL_SHM_ID_1 = atoi(__AFL_SHM_ID),
            shared_memory = shmat(__AFL_SHM_ID_1, 0LL, 0),//[2]
            shared_memory == (_BYTE *)-1LL) )
      {
...
      }
  }
  cur_value = _afl_prev_loc ^ unique_value; //[3]
  _afl_prev_loc ^= cur_value;
  _afl_prev_loc = (unsigned __int64)_afl_prev_loc >> 1;//[4]
  v8 = __CFADD__((*(_BYTE *)(shared_memory_2 + cur_value))++, 1);//[5]
  *(_BYTE *)(shared_memory_2 + cur_value) += v8;
  return v5 + 127;
}

```

퀴즈퀴즈

- [4]에 대해서 설명하시오
- hint : https://lcamtuf.coredump.cx/afl/technical_details.txt
```
  cur_location = <COMPILE_TIME_RANDOM>;
  shared_mem[cur_location ^ prev_location]++; 
  prev_location = cur_location >> 1;
```



## executor 
- forkserver
- persistence
- qemu-user
- unicorn
- frida
- nyx

### forkserver

탄생 배경
- fuzzing이란 무작위 입력값으로 프로그램을 실행하여 버그를 찾는 기법
- target 프로그램을 엄청나게 많은 횟수 실행해야 함
- target 프로그램을 더 빨리 실행할 수 있는 방법은 없을까? 



- fork
  - process를 복제하는 Syscall
  - 새로운 프로세스는 child, 기존 프로세스는 parent
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid;

    // The fork() function is called.
    pid = fork();

    // fork() will return -1 if it failed.
    if(pid < 0) {
        printf("Fork failed.\n");
        return 1;
    }

    // If pid is equal to 0, then the current process is the child process.
    if(pid == 0) {
        printf("This is the child process. PID: %d\n", getpid());
    }
    // If pid is greater than 0, then the current process is the parent.
    else {
        printf("This is the parent process. PID: %d, Child's PID: %d\n", getpid(), pid);
    }

    return 0;
}

```


forkserver에 대한 설명 ... 




### persistence


target function에 대한 설명 ... 
굳이 매번 새로운 process를 생성할 필요가 있는가 ...
단점도 언급
- side effect

### nyx
- snapshot




### 중간 요약
- forkserver
- persistence
- nyx (snapshot)
기본적으로 fuzzer의 executor는 이 3가지 방식에서 벗어나지 않음. (현재까지는) 단지 이 방법론을 구현하는 방법과 툴이 다를 뿐. 

### qemu-user

소스코드가 없을 때

- wine mode
- winafl이라는 강력한 라이벌
- forkserver

### unicorn


### frida


## 추천 타겟 유형



## 실습
- 각각의 타겟에 맞는 방식을 사용하여 fuzzing을 돌리시오.
  - BlackBox (ARK)
  - LibXML 
 
*note: 인간적으로 harness는 미리 짜서 주자.*
실습 의도 : 각각의 executor에 대해서 이해하고, 상황에 맞는 executor를 고를 능력이 있는가. 

## REF
- http://commondatastorage.googleapis.com/fuzzbench-reports/oss-fuzz-benchmarks/index.html
- https://aflplus.plus/papers/aflpp-woot2020.pdf
- https://lcamtuf.coredump.cx/afl/technical_details.txt
