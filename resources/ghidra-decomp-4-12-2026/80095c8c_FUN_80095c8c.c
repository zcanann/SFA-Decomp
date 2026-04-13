// Function: FUN_80095c8c
// Entry: 80095c8c
// Size: 280 bytes

void FUN_80095c8c(double param_1,double param_2,double param_3,double param_4)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  
  if ((double)FLOAT_803dff80 == param_4) {
    param_4 = (double)FLOAT_803dff9c;
  }
  iVar5 = 0;
  for (iVar1 = DAT_803ddeb0;
      (iVar5 < 10 &&
      ((*(char *)(iVar1 + 0x38) != '\0' || (*(float *)(iVar1 + 0x10) < FLOAT_803dff6c))));
      iVar1 = iVar1 + 0x3c) {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 < 10) {
    pfVar4 = (float *)(DAT_803ddeb0 + iVar5 * 0x3c);
    *pfVar4 = (float)param_1;
    pfVar4[1] = (float)param_2;
    pfVar4[2] = (float)param_3;
    DAT_803ddeb4 = DAT_803ddeb4 + 1;
    pfVar4[3] = (float)param_4;
    uVar2 = FUN_80022264((int)pfVar4[3],(int)(FLOAT_803dff7c * pfVar4[3]));
    uVar3 = FUN_80095da4(DAT_803ddeb0 + iVar5 * 0x3c,iVar5,uVar2);
    *(undefined *)(pfVar4 + 0xe) = uVar3;
    pfVar4[4] = FLOAT_803dff80;
    dVar6 = FUN_80293900((double)pfVar4[3]);
    pfVar4[5] = FLOAT_803dff6c / (float)((double)FLOAT_803dffa0 * dVar6);
  }
  return;
}

