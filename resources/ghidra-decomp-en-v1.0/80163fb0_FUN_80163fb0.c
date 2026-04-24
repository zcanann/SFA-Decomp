// Function: FUN_80163fb0
// Entry: 80163fb0
// Size: 64 bytes

void FUN_80163fb0(int param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x278) = 6;
  *(undefined4 *)(iVar1 + 0x290) = param_2;
  *(float *)(iVar1 + 0x294) = FLOAT_803db414 * FLOAT_803e2f98;
  FUN_80035f00();
  return;
}

