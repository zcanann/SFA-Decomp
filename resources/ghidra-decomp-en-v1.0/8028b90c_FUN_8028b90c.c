// Function: FUN_8028b90c
// Entry: 8028b90c
// Size: 128 bytes

/* WARNING: Removing unreachable block (ram,0x8028b960) */

undefined4 FUN_8028b90c(undefined4 param_1,undefined4 param_2,int param_3)

{
  if (param_3 == 0) {
    DAT_8033230c = 1;
    DAT_80332310 = 1;
    DAT_80332318 = param_1;
    DAT_8033231c = param_2;
    DAT_803d8394 = 0;
    DAT_803d8598 = DAT_803d8598 | 0x400;
    return 0;
  }
  return 0x703;
}

