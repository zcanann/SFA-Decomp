// Function: FUN_8019f93c
// Entry: 8019f93c
// Size: 188 bytes

void FUN_8019f93c(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e4280);
    if ((FLOAT_803e4260 < *(float *)(iVar1 + 0x30)) &&
       (*(float *)(iVar1 + 0x30) =
             FLOAT_803e4264 *
             (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e4270) +
             *(float *)(iVar1 + 0x30), *(float *)(iVar1 + 0x30) < FLOAT_803e4284)) {
      FUN_80099d84((double)FLOAT_803e4280,param_1,3,0);
    }
  }
  return;
}

