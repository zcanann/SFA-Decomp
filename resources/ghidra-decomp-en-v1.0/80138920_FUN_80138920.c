// Function: FUN_80138920
// Entry: 80138920
// Size: 192 bytes

undefined4 FUN_80138920(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) {
    if ((*(short *)(param_1 + 0xa0) < 0x30) && (0x28 < *(short *)(param_1 + 0xa0))) {
      uVar1 = 0;
    }
    else {
      iVar2 = FUN_8000b578(param_1,0x10);
      if (iVar2 == 0) {
        FUN_800393f8(param_1,iVar3 + 0x3a8,param_2,param_3,0xffffffff,0);
        uVar1 = 1;
      }
      else {
        uVar1 = 0;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

