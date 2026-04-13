// Function: FUN_8028c0f0
// Entry: 8028c0f0
// Size: 120 bytes

/* WARNING: Removing unreachable block (ram,0x8028c13c) */

undefined4 FUN_8028c0f0(int param_1,int param_2)

{
  if (param_2 == 0) {
    DAT_80332f70 = 0;
    DAT_80332f6c = 1;
    DAT_803d91f8 = DAT_803d91f8 | 0x400;
    DAT_80332f74 = param_1 + -1;
    DAT_803d8ff4 = 0;
    return 0;
  }
  return 0x703;
}

