// Function: FUN_801430e0
// Entry: 801430e0
// Size: 304 bytes

undefined4 FUN_801430e0(int param_1,int param_2)

{
  int iVar1;
  char cVar3;
  int iVar2;
  
  iVar1 = FUN_8014460c();
  if ((iVar1 == 0) &&
     (cVar3 = FUN_8013b368((double)FLOAT_803e2418,param_1,param_2), cVar3 != '\x01')) {
    if (*(int *)(param_2 + 0x7b0) == 0) {
      iVar1 = FUN_800221a0(0,6);
      if ((iVar1 < 5) && (-1 < iVar1)) {
        FUN_801444a4(param_1,param_2);
      }
      else {
        FUN_801441c0(param_1,param_2);
      }
    }
    else {
      iVar1 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (iVar2 = FUN_8000b578(param_1,0x10), iVar2 == 0)))) {
        FUN_800393f8(param_1,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
      }
      FUN_8013a3f0((double)FLOAT_803e251c,param_1,0x26,0);
      *(undefined *)(param_2 + 10) = 5;
    }
  }
  return 1;
}

