// Function: FUN_8000f4e0
// Entry: 8000f4e0
// Size: 48 bytes

void FUN_8000f4e0(undefined2 param_1,undefined2 param_2,undefined2 param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dc88d;
  (&DAT_803381d0)[uVar1 * 0x30] = param_1;
  (&DAT_803381d2)[uVar1 * 0x30] = param_2;
  (&DAT_803381d4)[uVar1 * 0x30] = param_3;
  return;
}

