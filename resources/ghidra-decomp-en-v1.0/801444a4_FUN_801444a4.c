// Function: FUN_801444a4
// Entry: 801444a4
// Size: 360 bytes

void FUN_801444a4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_800221a0(0,4);
  if (iVar1 == 2) {
    FUN_8013a3f0((double)FLOAT_803e2478,param_1,0x21,0);
    *(undefined *)(param_2 + 10) = 6;
  }
  else if (iVar1 < 2) {
    if (iVar1 == 0) {
      FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
      *(undefined *)(param_2 + 10) = 2;
    }
    else if (-1 < iVar1) {
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
  else if (iVar1 == 4) {
    FUN_8013a3f0((double)FLOAT_803e2518,param_1,0x25,0);
    *(undefined *)(param_2 + 10) = 2;
  }
  else if (iVar1 < 4) {
    FUN_8013a3f0((double)FLOAT_803e2478,param_1,0x23,0);
    *(undefined *)(param_2 + 10) = 7;
  }
  return;
}

