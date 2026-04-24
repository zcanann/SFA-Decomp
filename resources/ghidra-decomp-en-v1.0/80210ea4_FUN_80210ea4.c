// Function: FUN_80210ea4
// Entry: 80210ea4
// Size: 180 bytes

void FUN_80210ea4(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (((*(int *)(param_1 + 0x54) != 0) &&
      (iVar3 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), iVar3 != 0)) &&
     (*(short *)(iVar3 + 0x46) == 0x38c)) {
    FUN_80035f00();
    uVar1 = FUN_8002b9ec();
    FUN_8000bb18(uVar1,0xee);
    *(undefined *)(param_1 + 0x36) = 0xfa;
    *(undefined4 *)(param_1 + 0xf8) = 1;
    iVar2 = (int)*(short *)(iVar2 + 0x1e);
    if (iVar2 != -1) {
      FUN_800200e8(iVar2,1);
    }
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar3 + 0x24);
    *(float *)(param_1 + 0x28) = FLOAT_803e6760 + *(float *)(iVar3 + 0x28);
    *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(iVar3 + 0x2c);
  }
  return;
}

