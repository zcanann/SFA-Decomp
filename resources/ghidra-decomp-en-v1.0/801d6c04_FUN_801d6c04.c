// Function: FUN_801d6c04
// Entry: 801d6c04
// Size: 340 bytes

void FUN_801d6c04(void)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  undefined8 extraout_f1;
  float local_28;
  float local_24;
  float local_20 [8];
  
  psVar1 = (short *)FUN_802860d8();
  iVar5 = 0;
  DAT_803ad063 = '\0';
  DAT_803ad05a = '\0';
  uVar2 = FUN_8002fa48(extraout_f1,(double)FLOAT_803db414,psVar1,&DAT_803ad048);
  if (DAT_803ad05a != '\0') {
    *psVar1 = *psVar1 + DAT_803ad056;
  }
  puVar4 = &DAT_803ad048;
  for (iVar3 = 0; iVar3 < DAT_803ad063; iVar3 = iVar3 + 1) {
    switch(puVar4[0x13]) {
    case 1:
      iVar5 = 1;
      break;
    case 2:
      iVar5 = 2;
      break;
    case 3:
      iVar5 = 1;
      break;
    case 4:
      iVar5 = 2;
      break;
    case 9:
      FUN_8000bb18(psVar1,0x2f4);
    }
    puVar4 = puVar4 + 1;
  }
  if ((iVar5 != 0) &&
     ((FUN_8003842c(psVar1,iVar5 + -1,&local_28,&local_24,local_20,0), psVar1[0x50] != 0x1b ||
      (FLOAT_803e5498 <= *(float *)(psVar1 + 0x4c))))) {
    FUN_8000bae0((double)local_28,(double)local_24,(double)local_20[0],psVar1,0x415);
  }
  FUN_80286124(uVar2);
  return;
}

