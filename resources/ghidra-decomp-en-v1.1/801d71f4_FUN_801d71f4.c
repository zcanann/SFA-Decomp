// Function: FUN_801d71f4
// Entry: 801d71f4
// Size: 340 bytes

void FUN_801d71f4(void)

{
  short *psVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  undefined8 extraout_f1;
  float local_28;
  float local_24;
  float local_20 [8];
  
  psVar1 = (short *)FUN_8028683c();
  iVar4 = 0;
  DAT_803adcc3 = '\0';
  DAT_803adcba = '\0';
  FUN_8002fb40(extraout_f1,(double)FLOAT_803dc074);
  if (DAT_803adcba != '\0') {
    *psVar1 = *psVar1 + DAT_803adcb6;
  }
  puVar3 = &DAT_803adca8;
  for (iVar2 = 0; iVar2 < DAT_803adcc3; iVar2 = iVar2 + 1) {
    switch(puVar3[0x13]) {
    case 1:
      iVar4 = 1;
      break;
    case 2:
      iVar4 = 2;
      break;
    case 3:
      iVar4 = 1;
      break;
    case 4:
      iVar4 = 2;
      break;
    case 9:
      FUN_8000bb38((uint)psVar1,0x2f4);
    }
    puVar3 = puVar3 + 1;
  }
  if ((iVar4 != 0) &&
     ((FUN_80038524(psVar1,iVar4 + -1,&local_28,&local_24,local_20,0), psVar1[0x50] != 0x1b ||
      (FLOAT_803e6130 <= *(float *)(psVar1 + 0x4c))))) {
    FUN_8000bb00((double)local_28,(double)local_24,(double)local_20[0],(uint)psVar1,0x415);
  }
  FUN_80286888();
  return;
}

