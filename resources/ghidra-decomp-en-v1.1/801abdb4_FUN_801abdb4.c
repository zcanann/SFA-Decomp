// Function: FUN_801abdb4
// Entry: 801abdb4
// Size: 256 bytes

void FUN_801abdb4(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80020078(0xdc5);
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 4));
  if (uVar1 == 0) {
    FUN_8002b95c(param_1,1);
    iVar2 = FUN_8003811c(param_1);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      FUN_80020000(0xa9);
      *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8002b95c(param_1,0);
  }
  return;
}

