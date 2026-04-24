// Function: FUN_800e9870
// Entry: 800e9870
// Size: 192 bytes

void FUN_800e9870(uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  FUN_800200e8((&DAT_80311720)[param_1],param_2);
  DAT_803dd494 = (undefined)param_1;
  uRam803dd495 = (undefined)param_2;
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  if ((&DAT_80311810)[param_1] != 0) {
    uVar1 = FUN_8001ffb4();
    (&DAT_803a2fbc)[param_1] = uVar1;
  }
  return;
}

