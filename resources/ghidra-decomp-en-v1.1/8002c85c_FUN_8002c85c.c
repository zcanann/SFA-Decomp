// Function: FUN_8002c85c
// Entry: 8002c85c
// Size: 872 bytes

void FUN_8002c85c(short *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint extraout_r4;
  uint extraout_r4_00;
  code *pcVar4;
  
  if ((param_1[0x58] & 0x40U) != 0) {
    return;
  }
  if ((DAT_803dd7f8 & 1) != 0) {
    sVar1 = param_1[0x23];
    if (sVar1 != 0x4f3) {
      if (sVar1 < 0x4f3) {
        if (sVar1 != 0x1f) {
          if (0x1e < sVar1) {
            if (sVar1 != 0x69) {
              return;
            }
            FUN_8016effc((int)param_1);
            return;
          }
          if (sVar1 != 0) {
            return;
          }
        }
        FUN_802b6864((int)param_1);
        return;
      }
      if (sVar1 != 0x887) {
        if (0x886 < sVar1) {
          return;
        }
        if (sVar1 != 0x882) {
          return;
        }
      }
    }
    (**(code **)(**(int **)(param_1 + 0x34) + 8))(param_1);
    return;
  }
  uVar3 = (uint)*(byte *)((int)param_1 + 0xe5);
  if (((uVar3 != 0) && (*(int *)(param_1 + 0x62) == 0)) &&
     ((*(byte *)((int)param_1 + 0xe5) & 2) != 0)) {
    FUN_8002aba0((int)param_1);
    uVar3 = extraout_r4;
  }
  if (*(int *)(param_1 + 0x60) != 0) {
    if ((*(int *)(param_1 + 100) != 0) &&
       (iVar2 = *(int *)(*(int *)(param_1 + 100) + 0x54), iVar2 != 0)) {
      *(undefined4 *)(iVar2 + 0x50) = 0;
      *(undefined *)(*(int *)(*(int *)(param_1 + 100) + 0x54) + 0x71) = 0;
    }
    if (*(int *)(param_1 + 0x2a) == 0) {
      return;
    }
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x50) = 0;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x71) = 0;
    return;
  }
  if ((param_1[3] & 8U) == 0) {
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 0x10);
  }
  *(undefined4 *)(param_1 + 0x7e) = *(undefined4 *)(param_1 + 0x12);
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_1 + 0x82) = *(undefined4 *)(param_1 + 0x16);
  if (((*(byte *)((int)param_1 + 0xe5) != 0) && (*(int *)(param_1 + 0x62) == 0)) &&
     (((*(byte *)((int)param_1 + 0xe5) & 1) != 0 &&
      (param_1[0x73] =
            (short)(int)((float)((double)CONCAT44(0x43300000,(int)param_1[0x73] ^ 0x80000000) -
                                DOUBLE_803df530) - FLOAT_803dc074), param_1[0x73] < 1)))) {
    param_1[0x73] = 0;
    *(byte *)((int)param_1 + 0xe5) = *(byte *)((int)param_1 + 0xe5) & 0xfe;
    *(undefined *)(param_1 + 0x78) = 0;
    FUN_80028500(*(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4));
    (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7fb,0,0x50,0);
    param_3 = 0;
    param_4 = 0x32;
    param_5 = 0;
    param_6 = *DAT_803dd734;
    (**(code **)(param_6 + 0xc))(param_1,0x7fc);
    FUN_8000bb38((uint)param_1,0x47b);
    uVar3 = extraout_r4_00;
  }
  if ((param_1[0x58] & 0x8000U) == 0) {
    sVar1 = param_1[0x23];
    if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
      FUN_802b68f0(param_1,uVar3,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else {
      if (*(int **)(param_1 + 0x34) == (int *)0x0) goto LAB_8002cb50;
      pcVar4 = *(code **)(**(int **)(param_1 + 0x34) + 8);
      if (pcVar4 != (code *)0x0) {
        (*pcVar4)(param_1);
      }
    }
    FUN_8000e12c((int)param_1,(float *)(param_1 + 0xc),(float *)(param_1 + 0xe),
                 (float *)(param_1 + 0x10));
  }
LAB_8002cb50:
  if (*(int *)(param_1 + 0x2a) != 0) {
    if ((*(int *)(param_1 + 100) != 0) &&
       (iVar2 = *(int *)(*(int *)(param_1 + 100) + 0x54), iVar2 != 0)) {
      *(undefined4 *)(iVar2 + 0x50) = 0;
      *(undefined *)(*(int *)(*(int *)(param_1 + 100) + 0x54) + 0x71) = 0;
    }
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x50) = 0;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x71) = 0;
  }
  if (*(int *)(param_1 + 0x2c) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10f) = 0;
  }
  return;
}

