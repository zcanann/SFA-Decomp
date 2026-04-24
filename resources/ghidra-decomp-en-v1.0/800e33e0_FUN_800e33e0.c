// Function: FUN_800e33e0
// Entry: 800e33e0
// Size: 204 bytes

double FUN_800e33e0(int param_1,uint param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  
  if ((int)param_2 < 0) {
    iVar7 = 0;
  }
  else {
    iVar6 = DAT_803dd478 + -1;
    iVar5 = 0;
    while (iVar5 <= iVar6) {
      iVar4 = iVar6 + iVar5 >> 1;
      iVar7 = (&DAT_803a17e8)[iVar4];
      if (*(uint *)(iVar7 + 0x14) < param_2) {
        iVar5 = iVar4 + 1;
      }
      else {
        if (*(uint *)(iVar7 + 0x14) <= param_2) goto LAB_800e3454;
        iVar6 = iVar4 + -1;
      }
    }
    iVar7 = 0;
  }
LAB_800e3454:
  if ((iVar7 == 0) || (param_1 == 0)) {
    dVar8 = (double)FLOAT_803e0630;
  }
  else {
    fVar1 = *(float *)(iVar7 + 8) - *(float *)(param_1 + 0xc);
    fVar2 = *(float *)(iVar7 + 0xc) - *(float *)(param_1 + 0x10);
    fVar3 = *(float *)(iVar7 + 0x10) - *(float *)(param_1 + 0x14);
    dVar8 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  }
  return dVar8;
}

