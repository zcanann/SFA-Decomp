// Function: FUN_8028b98c
// Entry: 8028b98c
// Size: 120 bytes

/* WARNING: Removing unreachable block (ram,0x8028b9d8) */

undefined4 FUN_8028b98c(int param_1,int param_2)

{
  if (param_2 == 0) {
    DAT_8033230c = 1;
    DAT_80332310 = 0;
    DAT_80332314 = param_1 + -1;
    DAT_803d8394 = 0;
    DAT_803d8598 = DAT_803d8598 | 0x400;
    return 0;
  }
  return 0x703;
}

