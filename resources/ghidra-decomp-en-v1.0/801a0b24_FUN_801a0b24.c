// Function: FUN_801a0b24
// Entry: 801a0b24
// Size: 108 bytes

undefined4 FUN_801a0b24(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (((*(char *)(*(int *)(param_1 + 0xb8) + 0x15) == '\0') &&
      (*(float *)(*(int *)(param_1 + 0xb8) + 0x18) == FLOAT_803e42c0)) &&
     (iVar1 = (**(code **)(*DAT_803dcac0 + 0x14))(), iVar1 == 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

