// Function: FUN_80284638
// Entry: 80284638
// Size: 56 bytes

undefined4 FUN_80284638(uint param_1,undefined4 *param_2)

{
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = *(undefined4 *)(&DAT_803d4470 + (param_1 & 0xff) * 0x10);
  }
  return *(undefined4 *)(&DAT_803d446c + (param_1 & 0xff) * 0x10);
}

