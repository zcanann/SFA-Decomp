// Function: FUN_8021a938
// Entry: 8021a938
// Size: 300 bytes

void FUN_8021a938(int param_1)

{
  uint uVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)(piVar2 + 1) >> 6 & 1) == 0) {
    if ((*piVar2 == 0) &&
       (uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e)), uVar1 != 0)) {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0xbf | 0x40;
      *piVar2 = 2;
    }
    if ((*(byte *)(piVar2 + 1) >> 5 & 1) == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(*piVar2,param_1,0xffffffff);
    }
    else {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0xbf | 0x40;
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x76c);
      uVar1 = FUN_80020078(0x9f3);
      if (uVar1 == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(*piVar2,param_1,0x70);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(*piVar2,param_1,0x60);
      }
    }
  }
  return;
}

