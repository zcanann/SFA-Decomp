// Function: FUN_80271178
// Entry: 80271178
// Size: 336 bytes

void FUN_80271178(int *param_1,int *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int **ppiVar4;
  int **in_r9;
  
  uVar2 = (param_3 >> 8) + (uint)DAT_803de239;
  uVar1 = uVar2 & 0x1f;
  ppiVar4 = (int **)(&DAT_803bcfd0 + uVar1 * 3);
  if (param_2 == (int *)0x1) {
    param_2 = param_1 + 3;
    if (*(char *)((int)param_1 + 0x15) != -1) {
      if (*(byte *)((int)param_1 + 0x15) == uVar1) {
        return;
      }
      if (*param_2 != 0) {
        *(int *)(*param_2 + 4) = param_1[4];
      }
      if ((int *)param_1[4] == (int *)0x0) {
        (&DAT_803bcfd8)[(uint)*(byte *)((int)param_1 + 0x15) * 3] = *param_2;
      }
      else {
        *(int *)param_1[4] = *param_2;
      }
    }
    in_r9 = (int **)(&DAT_803bcfd8 + uVar1 * 3);
  }
  else if ((int)param_2 < 1) {
    if ((-1 < (int)param_2) &&
       (param_2 = param_1, in_r9 = ppiVar4, *(byte *)((int)param_1 + 9) != 0xff)) {
      if (*(byte *)((int)param_1 + 9) == uVar1) {
        return;
      }
      if (*param_1 != 0) {
        *(int *)(*param_1 + 4) = param_1[1];
      }
      if ((int *)param_1[1] == (int *)0x0) {
        (&DAT_803bcfd0)[(uint)*(byte *)((int)param_1 + 9) * 3] = *param_1;
      }
      else {
        *(int *)param_1[1] = *param_1;
      }
    }
  }
  else if ((int)param_2 < 3) {
    if (*(char *)((int)param_1 + 0x21) != -1) {
      return;
    }
    param_2 = param_1 + 6;
    in_r9 = (int **)(&DAT_803bcfd4 + uVar1 * 3);
  }
  *(byte *)((int)param_2 + 9) = (byte)uVar2 & 0x1f;
  piVar3 = *in_r9;
  *param_2 = (int)piVar3;
  if (piVar3 != (int *)0x0) {
    (*in_r9)[1] = (int)param_2;
  }
  param_2[1] = 0;
  *in_r9 = param_2;
  return;
}

