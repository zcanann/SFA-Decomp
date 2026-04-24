// Function: FUN_800e3330
// Entry: 800e3330
// Size: 172 bytes

double FUN_800e3330(double param_1,double param_2,uint param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  if ((int)param_3 < 0) {
    iVar6 = 0;
  }
  else {
    iVar5 = DAT_803dd478 + -1;
    iVar4 = 0;
    while (iVar4 <= iVar5) {
      iVar3 = iVar5 + iVar4 >> 1;
      iVar6 = (&DAT_803a17e8)[iVar3];
      if (*(uint *)(iVar6 + 0x14) < param_3) {
        iVar4 = iVar3 + 1;
      }
      else {
        if (*(uint *)(iVar6 + 0x14) <= param_3) goto LAB_800e33a4;
        iVar5 = iVar3 + -1;
      }
    }
    iVar6 = 0;
  }
LAB_800e33a4:
  if (iVar6 == 0) {
    dVar7 = (double)FLOAT_803e0630;
  }
  else {
    fVar1 = (float)((double)*(float *)(iVar6 + 8) - param_1);
    fVar2 = (float)((double)*(float *)(iVar6 + 0x10) - param_2);
    dVar7 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  }
  return dVar7;
}

