// Function: FUN_802ad964
// Entry: 802ad964
// Size: 240 bytes

void FUN_802ad964(undefined4 param_1,int param_2)

{
  *(undefined4 *)(param_2 + 0x3fc) = *(undefined4 *)(param_2 + 0x3f8);
  if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) {
    if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
      *(undefined **)(param_2 + 0x3f8) = &DAT_80333e30;
      *(undefined **)(param_2 + 0x400) = &DAT_80333bf8;
      return;
    }
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333d30;
    *(undefined **)(param_2 + 0x400) = &DAT_80333bf8;
    return;
  }
  if (*(int *)(param_2 + 0x7f8) != 0) {
    *(undefined2 **)(param_2 + 0x3f8) = &DAT_80333d70;
    *(undefined **)(param_2 + 0x400) = &DAT_80333eb0;
    return;
  }
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
    if (*(char *)(param_2 + 0x8b3) != '\0') {
      *(undefined **)(param_2 + 0x3f8) = &DAT_80333db0;
      *(undefined **)(param_2 + 0x400) = &DAT_80333eb0;
      return;
    }
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333df0;
    *(undefined **)(param_2 + 0x400) = &DAT_80333eb0;
    return;
  }
  if (*(char *)(param_2 + 0x8b3) != '\0') {
    *(undefined **)(param_2 + 0x3f8) = &DAT_80333cf0;
    *(undefined **)(param_2 + 0x400) = &DAT_80333eb0;
    return;
  }
  *(undefined **)(param_2 + 0x3f8) = &DAT_80333cb0;
  *(undefined **)(param_2 + 0x400) = &DAT_80333eb0;
  return;
}

