// Function: FUN_8028c070
// Entry: 8028c070
// Size: 128 bytes

/* WARNING: Removing unreachable block (ram,0x8028c0c4) */

undefined4 FUN_8028c070(undefined4 param_1,undefined4 param_2,int param_3)

{
  if (param_3 == 0) {
    DAT_80332f70 = 1;
    DAT_80332f78 = param_1;
    DAT_80332f7c = param_2;
    DAT_80332f6c = 1;
    DAT_803d91f8 = DAT_803d91f8 | 0x400;
    DAT_803d8ff4 = 0;
    return 0;
  }
  return 0x703;
}

