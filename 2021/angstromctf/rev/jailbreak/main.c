undefined8 FUN_001010b0(void)

{
  bool bVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  char *__modes;
  FILE *__stream;
  ulong uVar5;
  uint uVar6;
  int leet;
  ulong uVar7;
  long in_FS_OFFSET;
  char input [256];
  char local_148 [264];
  long local_40;
  
  bVar1 = true;
  leet = 0;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101620(1);
  uVar7 = 0;
LAB_00101148:
  do {
    pcVar3 = (char *)FUN_001015a0(0);
    puts(pcVar3);
    free(pcVar3);
    pcVar3 = fgets(input,0x100,stdin);
    if (pcVar3 == (char *)0x0) {
LAB_001013c8:
      FUN_00101620(5);
LAB_001013d2:
      if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    sVar4 = strcspn(input,"\n");
    input[sVar4] = '\0';
    if (leet != 0) {
      pcVar3 = (char *)FUN_001015a0(2);
      iVar2 = strcmp(input,pcVar3);
      free(pcVar3);
      uVar6 = 0x12;
      if (iVar2 != 0) {
        if (leet == 0x539) {
          pcVar3 = (char *)FUN_001015a0(0x17);
          iVar2 = strcmp(input,pcVar3);
          free(pcVar3);
          if (iVar2 == 0) {
            FUN_00101620(0x18);
            pcVar3 = (char *)FUN_001015a0(0x19);
            __modes = (char *)FUN_001015a0(0x1a);
            __stream = fopen(pcVar3,__modes);
            free(pcVar3);
            free(__modes);
            if (__stream == (FILE *)0x0) {
              FUN_00101620(0x1b);
            }
            else {
              fgets(local_148,0x100,__stream);
              sVar4 = strcspn(local_148,"\n");
              local_148[sVar4] = '\0';
              puts(local_148);
            }
            FUN_00101620(0x1c);
            goto LAB_001013d2;
          }
        }
        pcVar3 = (char *)FUN_001015a0(0x13);
        iVar2 = strcmp(input,pcVar3);
        free(pcVar3);
        if (iVar2 == 0) {
          leet = leet * 2;
          uVar6 = 0x15;
        }
        else {
          pcVar3 = (char *)FUN_001015a0(0x14);
          iVar2 = strcmp(input,pcVar3);
          free(pcVar3);
          uVar6 = 4;
          if (iVar2 == 0) {
            leet = leet * 2 + 1;
            uVar6 = 0x16;
          }
        }
      }
LAB_00101130:
      pcVar3 = (char *)FUN_001015a0(uVar6);
      puts(pcVar3);
      free(pcVar3);
      goto LAB_00101148;
    }
    pcVar3 = (char *)FUN_001015a0(2);
    iVar2 = strcmp(input,pcVar3);
    free(pcVar3);
    if (iVar2 == 0) {
      uVar6 = 3;
      if (!bVar1) {
        uVar6 = 8;
      }
      goto LAB_00101130;
    }
    pcVar3 = (char *)FUN_001015a0(6);
    iVar2 = strcmp(input,pcVar3);
    free(pcVar3);
    if (iVar2 == 0) {
      FUN_00101620(7);
      goto LAB_001013c8;
    }
    pcVar3 = (char *)FUN_001015a0(9);
    iVar2 = strcmp(input,pcVar3);
    free(pcVar3);
    uVar6 = 10;
    if (iVar2 == 0) goto LAB_00101130;
    pcVar3 = (char *)FUN_001015a0(0xb);
    iVar2 = strcmp(input,pcVar3);
    free(pcVar3);
    if (iVar2 == 0) {
      if (bVar1) {
        FUN_00101620(0xc);
        goto LAB_001013c8;
      }
      leet = 1;
      FUN_00101620(0xd);
    }
    else {
      uVar5 = FUN_00101640(input,0xf);
      if ((char)uVar5 == '\0') {
        uVar5 = FUN_00101640(input,0xe);
        if (((char)uVar5 == '\0') || ((char)uVar7 == '\0')) {
LAB_00101429:
          FUN_00101620(4);
        }
        else {
LAB_0010144e:
          bVar1 = false;
          FUN_00101620(0x11);
          uVar7 = 1;
        }
      }
      else {
        if ((char)uVar7 != '\0') {
          uVar5 = FUN_00101640(input,0xe);
          if ((char)uVar5 != '\0') goto LAB_0010144e;
          goto LAB_00101429;
        }
        FUN_00101620(0x10);
        uVar7 = uVar5 & 0xffffffff;
      }
    }
  } while( true );
}