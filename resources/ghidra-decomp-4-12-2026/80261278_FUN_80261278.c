// Function: FUN_80261278
// Entry: 80261278
// Size: 432 bytes

void FUN_80261278(ushort *param_1,uint param_2,short *param_3,short *param_4)

{
  ushort *puVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  
  *param_4 = 0;
  uVar3 = ((int)param_2 >> 1) + (uint)((int)param_2 < 0 && (param_2 & 1) != 0);
  *param_3 = 0;
  if (0 < (int)uVar3) {
    uVar4 = uVar3 >> 3;
    if (uVar4 != 0) {
      do {
        *param_3 = *param_3 + *param_1;
        *param_4 = *param_4 + ~*param_1;
        *param_3 = *param_3 + param_1[1];
        *param_4 = *param_4 + ~param_1[1];
        *param_3 = *param_3 + param_1[2];
        *param_4 = *param_4 + ~param_1[2];
        *param_3 = *param_3 + param_1[3];
        *param_4 = *param_4 + ~param_1[3];
        *param_3 = *param_3 + param_1[4];
        *param_4 = *param_4 + ~param_1[4];
        *param_3 = *param_3 + param_1[5];
        *param_4 = *param_4 + ~param_1[5];
        *param_3 = *param_3 + param_1[6];
        *param_4 = *param_4 + ~param_1[6];
        *param_3 = *param_3 + param_1[7];
        puVar1 = param_1 + 7;
        param_1 = param_1 + 8;
        *param_4 = *param_4 + ~*puVar1;
        uVar4 = uVar4 - 1;
      } while (uVar4 != 0);
      uVar3 = uVar3 & 7;
      if (uVar3 == 0) goto LAB_802613fc;
    }
    do {
      *param_3 = *param_3 + *param_1;
      uVar2 = *param_1;
      param_1 = param_1 + 1;
      *param_4 = *param_4 + ~uVar2;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
LAB_802613fc:
  if (*param_3 == -1) {
    *param_3 = 0;
  }
  if (*param_4 == -1) {
    *param_4 = 0;
    return;
  }
  return;
}

