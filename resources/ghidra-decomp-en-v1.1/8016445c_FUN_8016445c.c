// Function: FUN_8016445c
// Entry: 8016445c
// Size: 64 bytes

void FUN_8016445c(int param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x278) = 6;
  *(undefined4 *)(iVar1 + 0x290) = param_2;
  *(float *)(iVar1 + 0x294) = FLOAT_803dc074 * FLOAT_803e3c30;
  FUN_80035ff8(param_1);
  return;
}

