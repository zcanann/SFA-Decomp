// Function: FUN_8008979c
// Entry: 8008979c
// Size: 104 bytes

void FUN_8008979c(uint param_1,undefined param_2,undefined param_3,undefined param_4)

{
  if (DAT_803dddac == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    *(undefined *)(DAT_803dddac + 0x8c) = param_2;
    *(undefined *)(DAT_803dddac + 0x8d) = param_3;
    *(undefined *)(DAT_803dddac + 0x8e) = param_4;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  *(undefined *)(DAT_803dddac + 0x130) = param_2;
  *(undefined *)(DAT_803dddac + 0x131) = param_3;
  *(undefined *)(DAT_803dddac + 0x132) = param_4;
  return;
}

