// Function: FUN_802ad204
// Entry: 802ad204
// Size: 240 bytes

void FUN_802ad204(undefined4 param_1,int param_2)

{
  *(undefined4 *)(param_2 + 0x3fc) = *(undefined4 *)(param_2 + 0x3f8);
  if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) {
    if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
      *(undefined **)(param_2 + 0x3f8) = &DAT_803331d0;
      *(undefined **)(param_2 + 0x400) = &DAT_80332f98;
      return;
    }
    *(undefined **)(param_2 + 0x3f8) = &DAT_803330d0;
    *(undefined **)(param_2 + 0x400) = &DAT_80332f98;
    return;
  }
  if (*(int *)(param_2 + 0x7f8) != 0) {
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333110;
    *(undefined **)(param_2 + 0x400) = &DAT_80333250;
    return;
  }
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
    if (*(char *)(param_2 + 0x8b3) != '\0') {
      *(undefined **)(param_2 + 0x3f8) = &DAT_80333150;
      *(undefined **)(param_2 + 0x400) = &DAT_80333250;
      return;
    }
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333190;
    *(undefined **)(param_2 + 0x400) = &DAT_80333250;
    return;
  }
  if (*(char *)(param_2 + 0x8b3) != '\0') {
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333090;
    *(undefined **)(param_2 + 0x400) = &DAT_80333250;
    return;
  }
  *(undefined **)(param_2 + 0x3f8) = &DAT_80333050;
  *(undefined **)(param_2 + 0x400) = &DAT_80333250;
  return;
}

