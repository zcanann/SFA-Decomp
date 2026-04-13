// Function: FUN_80284d9c
// Entry: 80284d9c
// Size: 56 bytes

undefined4 FUN_80284d9c(uint param_1,undefined4 *param_2)

{
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = *(undefined4 *)(&DAT_803d50d0 + (param_1 & 0xff) * 0x10);
  }
  return *(undefined4 *)(&DAT_803d50cc + (param_1 & 0xff) * 0x10);
}

