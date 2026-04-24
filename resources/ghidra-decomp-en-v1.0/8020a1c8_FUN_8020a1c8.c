// Function: FUN_8020a1c8
// Entry: 8020a1c8
// Size: 532 bytes

void FUN_8020a1c8(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = FUN_802860dc();
  iVar5 = *(int *)(iVar2 + 0xb8);
  *(byte *)(iVar5 + 0x198) = *(byte *)(iVar5 + 0x198) & 0xef | 0x10;
  if (FLOAT_803e6510 < *(float *)(iVar5 + 0x18c)) {
    FUN_80016870(0x569);
    *(float *)(iVar5 + 0x18c) = *(float *)(iVar5 + 0x18c) - FLOAT_803db414;
    if (*(float *)(iVar5 + 0x18c) < FLOAT_803e6510) {
      *(float *)(iVar5 + 0x18c) = FLOAT_803e6510;
    }
  }
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 8) {
      FUN_800200e8(0x5db,0);
      (**(code **)(*DAT_803dcaac + 0x50))(2,0xf,1);
      (**(code **)(*DAT_803dcaac + 0x50))(2,0x10,1);
      FUN_800200e8(0xe7b,0);
      FUN_800552e8(0x79,0);
      FUN_80055000();
    }
    else if (bVar1 < 8) {
      if (bVar1 == 6) {
        iVar3 = FUN_80036e58(0x1e,iVar2,0);
        if ((iVar3 != 0) && (*(char *)(iVar2 + 0xeb) != '\0')) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,2);
          FUN_80037cb0(iVar2,iVar3);
        }
      }
      else if ((5 < bVar1) && (iVar3 = FUN_80036e58(0x1e,iVar2,0), iVar3 != 0)) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,0);
        FUN_80037d2c(iVar2,iVar3,1);
        *(float *)(iVar5 + 0x18c) = FLOAT_803e6514;
      }
    }
    else if (bVar1 < 10) {
      *(byte *)(iVar5 + 0x198) = *(byte *)(iVar5 + 0x198) & 0xfd | 2;
    }
  }
  if ((*(byte *)(iVar5 + 0x198) >> 1 & 1) != 0) {
    FUN_80099d84((double)FLOAT_803e6518,(double)FLOAT_803e651c,iVar2,6,0);
  }
  FUN_80286128(0);
  return;
}

