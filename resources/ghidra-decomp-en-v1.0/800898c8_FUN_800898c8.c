// Function: FUN_800898c8
// Entry: 800898c8
// Size: 84 bytes

void FUN_800898c8(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)

{
  if (DAT_803dd12c == 0) {
    *param_4 = 0xff;
    *param_3 = 0xff;
    *param_2 = 0xff;
    return;
  }
  param_1 = param_1 * 0xa4;
  *param_2 = *(undefined *)(DAT_803dd12c + param_1 + 0x78);
  *param_3 = *(undefined *)(DAT_803dd12c + param_1 + 0x79);
  *param_4 = *(undefined *)(DAT_803dd12c + param_1 + 0x7a);
  return;
}

