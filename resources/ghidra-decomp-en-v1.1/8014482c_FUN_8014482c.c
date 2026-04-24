// Function: FUN_8014482c
// Entry: 8014482c
// Size: 360 bytes

void FUN_8014482c(int param_1,int param_2)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  
  uVar1 = FUN_80022264(0,4);
  if (uVar1 == 2) {
    FUN_8013a778((double)FLOAT_803e3108,param_1,0x21,0);
    *(undefined *)(param_2 + 10) = 6;
  }
  else if ((int)uVar1 < 2) {
    if (uVar1 == 0) {
      FUN_8013a778((double)FLOAT_803e30d4,param_1,0,0);
      *(undefined *)(param_2 + 10) = 2;
    }
    else if (-1 < (int)uVar1) {
      iVar3 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (bVar2 = FUN_8000b598(param_1,0x10), !bVar2)))) {
        FUN_800394f0(param_1,iVar3 + 0x3a8,0x357,0,0xffffffff,0);
      }
      FUN_8013a778((double)FLOAT_803e31ac,param_1,0x26,0);
      *(undefined *)(param_2 + 10) = 5;
    }
  }
  else if (uVar1 == 4) {
    FUN_8013a778((double)FLOAT_803e31a8,param_1,0x25,0);
    *(undefined *)(param_2 + 10) = 2;
  }
  else if ((int)uVar1 < 4) {
    FUN_8013a778((double)FLOAT_803e3108,param_1,0x23,0);
    *(undefined *)(param_2 + 10) = 7;
  }
  return;
}

