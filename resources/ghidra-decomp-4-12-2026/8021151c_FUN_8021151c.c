// Function: FUN_8021151c
// Entry: 8021151c
// Size: 180 bytes

void FUN_8021151c(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (((*(int *)(param_1 + 0x54) != 0) &&
      (iVar3 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), iVar3 != 0)) &&
     (*(short *)(iVar3 + 0x46) == 0x38c)) {
    FUN_80035ff8(param_1);
    uVar1 = FUN_8002bac4();
    FUN_8000bb38(uVar1,0xee);
    *(undefined *)(param_1 + 0x36) = 0xfa;
    *(undefined4 *)(param_1 + 0xf8) = 1;
    uVar1 = (uint)*(short *)(iVar2 + 0x1e);
    if (uVar1 != 0xffffffff) {
      FUN_800201ac(uVar1,1);
    }
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar3 + 0x24);
    *(float *)(param_1 + 0x28) = FLOAT_803e73f8 + *(float *)(iVar3 + 0x28);
    *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(iVar3 + 0x2c);
  }
  return;
}

