// Function: FUN_802718dc
// Entry: 802718dc
// Size: 336 bytes

void FUN_802718dc(int *param_1,int *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int *in_r9;
  
  uVar2 = (param_3 >> 8) + (uint)DAT_803deeb9;
  uVar1 = uVar2 & 0x1f;
  piVar4 = &DAT_803bdc30 + uVar1 * 3;
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
        (&DAT_803bdc38)[(uint)*(byte *)((int)param_1 + 0x15) * 3] = *param_2;
      }
      else {
        *(int *)param_1[4] = *param_2;
      }
    }
    in_r9 = &DAT_803bdc38 + uVar1 * 3;
  }
  else if ((int)param_2 < 1) {
    if ((-1 < (int)param_2) &&
       (param_2 = param_1, in_r9 = piVar4, *(byte *)((int)param_1 + 9) != 0xff)) {
      if (*(byte *)((int)param_1 + 9) == uVar1) {
        return;
      }
      if (*param_1 != 0) {
        *(int *)(*param_1 + 4) = param_1[1];
      }
      if ((int *)param_1[1] == (int *)0x0) {
        (&DAT_803bdc30)[(uint)*(byte *)((int)param_1 + 9) * 3] = *param_1;
      }
      else {
        *(int *)param_1[1] = *param_1;
      }
    }
  }
  else if ((int)param_2 < 3) {
    param_2 = param_1 + 6;
    if (*(char *)((int)param_1 + 0x21) != -1) {
      return;
    }
    in_r9 = &DAT_803bdc34 + uVar1 * 3;
  }
  *(byte *)((int)param_2 + 9) = (byte)uVar2 & 0x1f;
  iVar3 = *in_r9;
  *param_2 = iVar3;
  if (iVar3 != 0) {
    *(int **)(*in_r9 + 4) = param_2;
  }
  param_2[1] = 0;
  *in_r9 = (int)param_2;
  return;
}

