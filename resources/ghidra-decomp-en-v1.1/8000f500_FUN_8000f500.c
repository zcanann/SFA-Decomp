// Function: FUN_8000f500
// Entry: 8000f500
// Size: 48 bytes

void FUN_8000f500(undefined2 param_1,undefined2 param_2,undefined2 param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dd50d;
  (&DAT_80338e30)[uVar1 * 0x30] = param_1;
  (&DAT_80338e32)[uVar1 * 0x30] = param_2;
  (&DAT_80338e34)[uVar1 * 0x30] = param_3;
  return;
}

