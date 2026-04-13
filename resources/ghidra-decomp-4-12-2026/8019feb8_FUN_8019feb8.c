// Function: FUN_8019feb8
// Entry: 8019feb8
// Size: 188 bytes

void FUN_8019feb8(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    if (FLOAT_803e4ef8 < *(float *)(iVar1 + 0x30)) {
      *(float *)(iVar1 + 0x30) =
           FLOAT_803e4efc *
           (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4f08) +
           *(float *)(iVar1 + 0x30);
      if ((double)*(float *)(iVar1 + 0x30) < (double)FLOAT_803e4f1c) {
        FUN_8009a010((double)FLOAT_803e4f18,(double)*(float *)(iVar1 + 0x30),param_1,3,(int *)0x0);
      }
    }
  }
  return;
}

