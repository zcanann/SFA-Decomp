// Function: FUN_80138ca8
// Entry: 80138ca8
// Size: 192 bytes

undefined4 FUN_80138ca8(int param_1,ushort param_2,short param_3)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) {
    if ((*(short *)(param_1 + 0xa0) < 0x30) && (0x28 < *(short *)(param_1 + 0xa0))) {
      uVar1 = 0;
    }
    else {
      bVar2 = FUN_8000b598(param_1,0x10);
      if (bVar2) {
        uVar1 = 0;
      }
      else {
        FUN_800394f0(param_1,iVar3 + 0x3a8,param_2,param_3,0xffffffff,0);
        uVar1 = 1;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

