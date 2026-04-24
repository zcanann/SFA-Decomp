// Function: FUN_8021a290
// Entry: 8021a290
// Size: 300 bytes

void FUN_8021a290(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)(piVar2 + 1) >> 6 & 1) == 0) {
    if ((*piVar2 == 0) &&
       (iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e)), iVar1 != 0)) {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0xbf | 0x40;
      *piVar2 = 2;
    }
    if ((*(byte *)(piVar2 + 1) >> 5 & 1) == 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(*piVar2,param_1,0xffffffff);
    }
    else {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0xbf | 0x40;
      (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x76c);
      iVar1 = FUN_8001ffb4(0x9f3);
      if (iVar1 == 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(*piVar2,param_1,0x70);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(*piVar2,param_1,0x60);
      }
    }
  }
  return;
}

