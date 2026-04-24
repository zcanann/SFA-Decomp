// Function: FUN_801a10a0
// Entry: 801a10a0
// Size: 108 bytes

undefined4 FUN_801a10a0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (((*(char *)(*(int *)(param_1 + 0xb8) + 0x15) == '\0') &&
      (*(float *)(*(int *)(param_1 + 0xb8) + 0x18) == FLOAT_803e4f58)) &&
     (iVar1 = (**(code **)(*DAT_803dd740 + 0x14))(), iVar1 == 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

