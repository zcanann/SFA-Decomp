// Function: FUN_80095a00
// Entry: 80095a00
// Size: 280 bytes

void FUN_80095a00(double param_1,double param_2,double param_3,double param_4)

{
  int iVar1;
  undefined4 uVar2;
  undefined uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  
  if ((double)FLOAT_803df300 == param_4) {
    param_4 = (double)FLOAT_803df31c;
  }
  iVar5 = 0;
  for (iVar1 = DAT_803dd230;
      (iVar5 < 10 &&
      ((*(char *)(iVar1 + 0x38) != '\0' || (*(float *)(iVar1 + 0x10) < FLOAT_803df2ec))));
      iVar1 = iVar1 + 0x3c) {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 < 10) {
    pfVar4 = (float *)(DAT_803dd230 + iVar5 * 0x3c);
    *pfVar4 = (float)param_1;
    pfVar4[1] = (float)param_2;
    pfVar4[2] = (float)param_3;
    DAT_803dd234 = DAT_803dd234 + 1;
    pfVar4[3] = (float)param_4;
    uVar2 = FUN_800221a0((int)pfVar4[3],(int)(FLOAT_803df2fc * pfVar4[3]));
    uVar3 = FUN_80095b18((double)pfVar4[3],DAT_803dd230 + iVar5 * 0x3c,iVar5,uVar2);
    *(undefined *)(pfVar4 + 0xe) = uVar3;
    pfVar4[4] = FLOAT_803df300;
    dVar6 = (double)FUN_802931a0((double)pfVar4[3]);
    pfVar4[5] = FLOAT_803df2ec / (float)((double)FLOAT_803df320 * dVar6);
  }
  return;
}

