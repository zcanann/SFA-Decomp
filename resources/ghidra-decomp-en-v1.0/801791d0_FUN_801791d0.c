// Function: FUN_801791d0
// Entry: 801791d0
// Size: 460 bytes

void FUN_801791d0(short *param_1,int param_2)

{
  short sVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  FUN_80037964(param_1,4);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_80178338;
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  param_1[0x58] = param_1[0x58] | 0x6000;
  pfVar2[4] = (float)(int)*(short *)(param_2 + 0x1e);
  pfVar2[6] = (float)(int)*(short *)(param_2 + 0x20);
  pfVar2[3] = FLOAT_803e3654;
  sVar1 = param_1[0x23];
  if (sVar1 < 0x11b) {
    if (sVar1 == 0xc4) {
LAB_801792a8:
      pfVar2[5] = 9.52883e-44;
      goto LAB_801792e8;
    }
    if (sVar1 < 0xc4) {
      if (sVar1 == 0xc1) goto LAB_801792a8;
    }
    else if (sVar1 == 200) {
      pfVar2[3] = FLOAT_803e3684;
      goto LAB_801792e8;
    }
  }
  else {
    if (sVar1 == 0x13e) {
LAB_801792c0:
      *(undefined2 *)(pfVar2 + 7) = 0x33e;
      *(undefined2 *)((int)pfVar2 + 0x1e) = 0x33f;
      goto LAB_801792e8;
    }
    if (sVar1 < 0x13e) {
      if (sVar1 < 0x11d) {
        pfVar2[5] = 2.129974e-43;
        goto LAB_801792e8;
      }
    }
    else if (sVar1 == 0x37a) goto LAB_801792c0;
  }
  pfVar2[5] = -NAN;
LAB_801792e8:
  FUN_80037200(param_1,0xe);
  dVar3 = (double)FUN_80293e80((double)((FLOAT_803e364c *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e3678)) / FLOAT_803e3650));
  *pfVar2 = (float)dVar3;
  dVar3 = (double)FUN_80294204((double)((FLOAT_803e364c *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e3678)) / FLOAT_803e3650));
  pfVar2[1] = (float)dVar3;
  pfVar2[2] = -(*pfVar2 * *(float *)(param_1 + 6) + pfVar2[1] * *(float *)(param_1 + 10));
  return;
}

