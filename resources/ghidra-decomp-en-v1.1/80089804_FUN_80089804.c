// Function: FUN_80089804
// Entry: 80089804
// Size: 104 bytes

void FUN_80089804(uint param_1,undefined param_2,undefined param_3,undefined param_4)

{
  if (DAT_803dddac == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    *(undefined *)(DAT_803dddac + 0x84) = param_2;
    *(undefined *)(DAT_803dddac + 0x85) = param_3;
    *(undefined *)(DAT_803dddac + 0x86) = param_4;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  *(undefined *)(DAT_803dddac + 0x128) = param_2;
  *(undefined *)(DAT_803dddac + 0x129) = param_3;
  *(undefined *)(DAT_803dddac + 0x12a) = param_4;
  return;
}

