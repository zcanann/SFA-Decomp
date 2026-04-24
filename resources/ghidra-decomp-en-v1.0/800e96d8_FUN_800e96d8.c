// Function: FUN_800e96d8
// Entry: 800e96d8
// Size: 108 bytes

void FUN_800e96d8(uint param_1)

{
  undefined4 uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  if ((&DAT_80311810)[param_1] != 0) {
    uVar1 = FUN_8001ffb4();
    (&DAT_803a2fbc)[param_1] = uVar1;
  }
  return;
}

