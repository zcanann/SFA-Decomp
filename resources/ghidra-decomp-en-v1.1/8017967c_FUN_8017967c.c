// Function: FUN_8017967c
// Entry: 8017967c
// Size: 460 bytes

void FUN_8017967c(undefined2 *param_1,int param_2)

{
  short sVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  FUN_80037a5c((int)param_1,4);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801787e4;
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  param_1[0x58] = param_1[0x58] | 0x6000;
  pfVar2[4] = (float)(int)*(short *)(param_2 + 0x1e);
  pfVar2[6] = (float)(int)*(short *)(param_2 + 0x20);
  pfVar2[3] = FLOAT_803e42ec;
  sVar1 = param_1[0x23];
  if (sVar1 < 0x11b) {
    if (sVar1 == 0xc4) {
LAB_80179754:
      pfVar2[5] = 9.52883e-44;
      goto LAB_80179794;
    }
    if (sVar1 < 0xc4) {
      if (sVar1 == 0xc1) goto LAB_80179754;
    }
    else if (sVar1 == 200) {
      pfVar2[3] = FLOAT_803e431c;
      goto LAB_80179794;
    }
  }
  else {
    if (sVar1 == 0x13e) {
LAB_8017976c:
      *(undefined2 *)(pfVar2 + 7) = 0x33e;
      *(undefined2 *)((int)pfVar2 + 0x1e) = 0x33f;
      goto LAB_80179794;
    }
    if (sVar1 < 0x13e) {
      if (sVar1 < 0x11d) {
        pfVar2[5] = 2.12997e-43;
        goto LAB_80179794;
      }
    }
    else if (sVar1 == 0x37a) goto LAB_8017976c;
  }
  pfVar2[5] = -NAN;
LAB_80179794:
  FUN_800372f8((int)param_1,0xe);
  dVar3 = (double)FUN_802945e0();
  *pfVar2 = (float)dVar3;
  dVar3 = (double)FUN_80294964();
  pfVar2[1] = (float)dVar3;
  pfVar2[2] = -(*pfVar2 * *(float *)(param_1 + 6) + pfVar2[1] * *(float *)(param_1 + 10));
  return;
}

