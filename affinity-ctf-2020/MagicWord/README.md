# Magic Word
### Category: Reverse Engineering

The provided `magicword` binary decompiles its main function into this scary looking block:

```c
undefined8 main(void)

{
  char cVar1;
  bool bVar2;
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_f8 [32];
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_d8 [32];
  int local_b8 [4];
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  allocator<char> local_6a;
  allocator<char> local_69;
  basic_string *local_68 [4];
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_48 [44];
  int local_1c;
  
  local_b8[0] = 0x54;
  local_b8[1] = 0x6f;
  local_b8[2] = 0x74;
  local_b8[3] = 0x61;
  local_a8 = 0x6c;
  local_a4 = 0x6c;
  local_a0 = 0x79;
  local_9c = 0x52;
  local_98 = 0x61;
  local_94 = 0x6e;
  local_90 = 100;
  local_8c = 0x6f;
  local_88 = 0x6d;
  local_84 = 0x43;
  local_80 = 0x68;
  local_7c = 0x61;
  local_78 = 0x72;
  local_74 = 0x73;
  allocator();
  basic_string((char *)local_d8,(allocator *)&DAT_0010407a);
  ~allocator(&local_6a);
  local_1c = 0;
  while (local_1c < 0x12) {
    cVar1 = numToASCII(local_b8[local_1c]);
    operator+=(local_d8,cVar1);
    local_1c = local_1c + 1;
  }
  allocator();
  basic_string((char *)local_f8,(allocator *)&DAT_0010407a);
  ~allocator(&local_69);
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"Please provide the input\n");
  operator>><char,std--char_traits<char>,std--allocator<char>>
            ((basic_istream *)cin,(basic_string *)local_f8);
  bVar2 = operator!=<char,std--char_traits<char>,std--allocator<char>>
                    ((basic_string *)local_f8,(basic_string *)local_d8);
  if (bVar2 == false) {
    returnFlag[abi:cxx11]();
    operator+<char,std--char_traits<char>,std--allocator<char>>(local_68,(char *)local_48);
    operator<<<char,std--char_traits<char>,std--allocator<char>>
              ((basic_ostream *)cout,(basic_string *)local_68);
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_68);
    ~basic_string(local_48);
  }
  else {
    operator<<<std--char_traits<char>>((basic_ostream *)cout,"Incorrect Input\n");
  }
  ~basic_string(local_f8);
  ~basic_string(local_d8);
  return 0;
}
```

Zooming in on this particular section:

```c
  local_b8[0] = 0x54;
  local_b8[1] = 0x6f;
  local_b8[2] = 0x74;
  local_b8[3] = 0x61;
  local_a8 = 0x6c;
  local_a4 = 0x6c;
  local_a0 = 0x79;
  local_9c = 0x52;
  local_98 = 0x61;
  local_94 = 0x6e;
  local_90 = 100;
  local_8c = 0x6f;
  local_88 = 0x6d;
  local_84 = 0x43;
  local_80 = 0x68;
  local_7c = 0x61;
  local_78 = 0x72;
  local_74 = 0x73;
  allocator();
  basic_string((char *)local_d8,(allocator *)&DAT_0010407a);
  ~allocator(&local_6a);
  local_1c = 0;
  while (local_1c < 0x12) {
    cVar1 = numToASCII(local_b8[local_1c]);
```

I can see that there are 18 variables being assigned. The while loop iterates from 0 to 18 (18 is 0x12) calling `numToAscii` on that index of `local_b8`. From the positions of where the variables were initialized in memory, I can see that `local_a8` to `local_74` can all be referenced as offsets from `local_b8`.

Converting the variable hex values to ascii (`0x54=T`, `0x6f=o` ...), we get `TotallyRandomChars`.

Inputting this string into the program returns the flag.
```
Please provide the input
TotallyRandomChars
AFFCTF{h4v3AG00dD4y}
```