// Function: FUN_80048ba4
// Entry: 80048ba4
// Size: 88 bytes

void FUN_80048ba4(int param_1,int *param_2,int *param_3,undefined4 *param_4,int param_5)

{
  if (DAT_8035f45c == 0) {
    return;
  }
  if (DAT_8035f460 == 0) {
    return;
  }
  param_1 = DAT_8035f45c + param_1;
  *param_2 = (int)*(short *)(param_1 + 0x1c);
  *param_3 = (int)*(short *)(param_1 + 0x1e);
  *param_4 = *(undefined4 *)(DAT_8035f45c + *(int *)(DAT_8035f460 + param_5 * 4 + 0x18) + 4);
  return;
}

