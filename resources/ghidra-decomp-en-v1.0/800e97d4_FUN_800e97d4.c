// Function: FUN_800e97d4
// Entry: 800e97d4
// Size: 156 bytes

undefined FUN_800e97d4(uint param_1)

{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  if (param_1 != (int)DAT_803dd494) {
    DAT_803dd494 = (char)param_1;
    if ((((int)param_1 < 0) || (0x77 < (int)param_1)) || ((&DAT_80311720)[param_1] == 0)) {
      uRam803dd495 = 0;
    }
    else {
      uRam803dd495 = FUN_8001ffb4();
    }
  }
  return uRam803dd495;
}

