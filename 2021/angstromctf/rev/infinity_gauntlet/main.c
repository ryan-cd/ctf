undefined8 main(void)

{
  int inputLength2;
  int random_int;
  uint random2_uint;
  int iVar4;
  FILE *__stream;
  size_t inputLength;
  time_t tVar6;
  undefined8 uVar7;
  byte bVar8;
  uint contains_flag_byte;
  uint uVar10;
  byte *__s;
  uint i;
  ulong uVar12;
  long in_FS_OFFSET;
  uint local_14c;
  byte input [264];
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Couldn\'t find a flag file.");
    uVar7 = 1;
  }
  else {
    __s = input;
    fgets((char *)__s,0x100,__stream);
    fclose(__stream);
    inputLength = strcspn((char *)__s,"\n");
    inputLength2 = (int)inputLength;
    input[inputLength2] = 0;
    if (inputLength2 != 0) {
      bVar8 = 0;
      do {
        *__s = *__s ^ bVar8;
        bVar8 = bVar8 + 0x11;
        __s = __s + 1;
      } while (bVar8 != (byte)((char)inputLength * '\x11'));
    }
    i = 1;
    tVar6 = time((time_t *)0x0);
    srand((uint)tVar6);
    puts("Welcome to the infinity gauntlet!");
    puts("If you complete the gauntlet, you\'ll get the flag!");
    while( true ) {
      printf("=== ROUND %d ===\n",(ulong)i);
      random_int = rand();
      if ((int)i < 0x32) {
        random_int = rand();
        contains_flag_byte = (uint)(random_int >> 0x1f) >> 0x10;
        contains_flag_byte = (random_int + contains_flag_byte & 0xffff) - contains_flag_byte;
      }
      else {
        contains_flag_byte = ((random_int % (inputLength2 + i)) & 0xff) << 8 | (uint)input[random_int % inputLength2];
      }
      random2_uint = rand();
      if ((random2_uint & 1) == 0) {
        random2_uint = rand();
        if ((random2_uint & 3) == 0) {
          random_int = rand();
          iVar4 = rand();
          printf("bar(?, %u, %u) = %u\n",(ulong)(uint)(random_int % 0x539),(ulong)(uint)(iVar4 % 0x539));
        }
        else {
          uVar10 = (uint)((int)random2_uint >> 0x1f) >> 0x1e;
          random_int = (random2_uint + uVar10 & 3) - uVar10;
          if (random_int == 1) {
            random_int = rand();
            rand();
            printf("bar(%u, ?, %u) = %u\n",(long)random_int % 0x539 & 0xffffffff);
          }
          else {
            if (random_int == 2) {
              random_int = rand();
              rand();
              printf("bar(%u, %u, ?) = %u\n",(long)random_int % 0x539 & 0xffffffff);
            }
            else {
              if (contains_flag_byte < 0x53a) {
                random2_uint = rand();
                uVar12 = (ulong)random2_uint % (ulong)contains_flag_byte;
              }
              else {
                random_int = rand();
                uVar12 = (ulong)(uint)(random_int % 0x539);
              }
              printf("bar(%u, %u, %u) = ?\n",(ulong)contains_flag_byte % uVar12,uVar12);
            }
          }
        }
      }
      else {
        random_int = rand();
        if (random_int % 3 == 0) {
          random_int = rand();
          printf("foo(?, %u) = %u\n",(ulong)(uint)(random_int % 0x539),
                 (ulong)(random_int % 0x539 + 1U ^ contains_flag_byte ^ 0x539));
        }
        else {
          if (random_int % 3 == 1) {
            random_int = rand();
            printf("foo(%u, ?) = %u\n",(ulong)(uint)(random_int % 0x539),
                   (ulong)(contains_flag_byte + 1 ^ random_int % 0x539 ^ 0x539));
          }
          else {
            random_int = rand();
            printf("foo(%u, %u) = ?\n",(ulong)(random_int % 0x539 + 1U ^ contains_flag_byte ^ 0x539),
                   (ulong)(uint)(random_int % 0x539));
          }
        }
      }
      __isoc99_scanf(&DAT_001020c3);
      if (local_14c != contains_flag_byte) break;
      i = i + 1;
      printf("Correct! Maybe round %d will get you the flag ;)\n",(ulong)i);
    }
    puts("Wrong!");
    uVar7 = 0;
  }
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar7;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}