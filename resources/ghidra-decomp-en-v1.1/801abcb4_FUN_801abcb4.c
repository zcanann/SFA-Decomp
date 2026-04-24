// Function: FUN_801abcb4
// Entry: 801abcb4
// Size: 256 bytes

void FUN_801abcb4(int param_1,int param_2)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 4));
  if (uVar2 != 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8002b95c(param_1,1);
    return;
  }
  FUN_8002b95c(param_1,0);
  uVar2 = FUN_80020078(0xa9);
  if (uVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    iVar3 = FUN_8003809c(param_1,0xa9);
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      FUN_8001ffac(0xa9);
      bVar1 = true;
      goto LAB_801abd84;
    }
  }
  bVar1 = false;
LAB_801abd84:
  if (bVar1) {
    *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
  }
  return;
}

