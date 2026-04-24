// Function: FUN_801ab700
// Entry: 801ab700
// Size: 256 bytes

void FUN_801ab700(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 4));
  if (iVar2 != 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8002b884(param_1,1);
    return;
  }
  FUN_8002b884(param_1,0);
  iVar2 = FUN_8001ffb4(0xa9);
  if (iVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    iVar2 = FUN_80037fa4(param_1,0xa9);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      FUN_8001fee8(0xa9);
      bVar1 = true;
      goto LAB_801ab7d0;
    }
  }
  bVar1 = false;
LAB_801ab7d0:
  if (bVar1) {
    *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
  }
  return;
}

