// Function: FUN_8025f52c
// Entry: 8025f52c
// Size: 184 bytes

undefined4 FUN_8025f52c(int param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  if (((param_1 < 0) || (1 < param_1)) || ((&DAT_803aff4c)[param_1 * 0x44] == 0)) {
    uVar1 = 0xffffff80;
  }
  else {
    FUN_80243e74();
    if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
      uVar1 = 0xfffffffd;
    }
    else if ((&DAT_803afe44)[param_1 * 0x44] == -1) {
      uVar1 = 0xffffffff;
    }
    else {
      (&DAT_803afe44)[param_1 * 0x44] = 0xffffffff;
      uVar1 = 0;
      *(undefined4 *)(&DAT_803aff10 + param_1 * 0x110) = 0;
      *param_2 = &DAT_803afe40 + param_1 * 0x44;
    }
    FUN_80243e9c();
  }
  return uVar1;
}

