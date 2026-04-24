// Function: FUN_80184d4c
// Entry: 80184d4c
// Size: 316 bytes

void FUN_80184d4c(void)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  char in_r8;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_80286838();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b660(iVar1);
  if (*(short *)(iVar1 + 0x46) == 0x3d6) {
    iVar4 = 0;
    pcVar3 = &DAT_803dca24;
    iVar6 = 7;
    do {
      if (*pcVar3 == *(char *)(*(int *)(iVar2 + 0x34) + 8)) {
        iVar4 = iVar4 + 1;
        if (iVar4 == 7) {
          iVar4 = 0;
        }
        *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dca24)[iVar4];
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  if (*(short *)(iVar5 + 0x10) == 0) {
    if (*(int *)(iVar1 + 0xf8) == 0) {
      if (in_r8 == '\0') goto LAB_80184e70;
    }
    else if (in_r8 != -1) goto LAB_80184e70;
    FUN_8003b9ec(iVar1);
    if ((in_r8 != '\0') && (*(char *)(iVar1 + 0x36) != '\0')) {
      FUN_80097568((double)FLOAT_803e4698,(double)FLOAT_803e469c,iVar1,5,
                   (int)*(short *)(iVar5 + 0x22) & 0xff,1,0x14,0,0);
    }
  }
LAB_80184e70:
  FUN_80286884();
  return;
}

