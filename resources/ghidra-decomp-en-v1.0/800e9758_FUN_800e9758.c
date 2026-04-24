// Function: FUN_800e9758
// Entry: 800e9758
// Size: 124 bytes

uint FUN_800e9758(uint param_1,uint param_2)

{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  if (param_1 != DAT_803dd48c) {
    DAT_803dd48c = param_1;
    iRam803dd490 = FUN_8001ffb4((&DAT_80311810)[param_1]);
  }
  return iRam803dd490 >> (param_2 & 0x3f) & 1;
}

