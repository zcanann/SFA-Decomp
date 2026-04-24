// Function: FUN_80089578
// Entry: 80089578
// Size: 104 bytes

void FUN_80089578(uint param_1,undefined param_2,undefined param_3,undefined param_4)

{
  if (DAT_803dd12c == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    *(undefined *)(DAT_803dd12c + 0x84) = param_2;
    *(undefined *)(DAT_803dd12c + 0x85) = param_3;
    *(undefined *)(DAT_803dd12c + 0x86) = param_4;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  *(undefined *)(DAT_803dd12c + 0x128) = param_2;
  *(undefined *)(DAT_803dd12c + 0x129) = param_3;
  *(undefined *)(DAT_803dd12c + 0x12a) = param_4;
  return;
}

