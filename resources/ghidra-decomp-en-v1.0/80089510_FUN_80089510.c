// Function: FUN_80089510
// Entry: 80089510
// Size: 104 bytes

void FUN_80089510(uint param_1,undefined param_2,undefined param_3,undefined param_4)

{
  if (DAT_803dd12c == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    *(undefined *)(DAT_803dd12c + 0x8c) = param_2;
    *(undefined *)(DAT_803dd12c + 0x8d) = param_3;
    *(undefined *)(DAT_803dd12c + 0x8e) = param_4;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  *(undefined *)(DAT_803dd12c + 0x130) = param_2;
  *(undefined *)(DAT_803dd12c + 0x131) = param_3;
  *(undefined *)(DAT_803dd12c + 0x132) = param_4;
  return;
}

