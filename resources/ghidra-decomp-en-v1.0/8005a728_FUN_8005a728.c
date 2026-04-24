// Function: FUN_8005a728
// Entry: 8005a728
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x8005a894) */

undefined4 FUN_8005a728(uint param_1,uint param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float *pfVar9;
  undefined4 uVar10;
  uint uVar11;
  int iVar12;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  fVar1 = FLOAT_803debb4 *
          (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803debc0);
  fVar2 = FLOAT_803debb4 *
          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803debc0);
  fVar3 = FLOAT_803debec;
  fVar4 = FLOAT_803debf0;
  if (param_3 != 0) {
    fVar3 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8a) ^ 0x80000000) -
                   DOUBLE_803debc0);
    fVar4 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8c) ^ 0x80000000) -
                   DOUBLE_803debc0);
  }
  pfVar9 = (float *)&DAT_8038793c;
  iVar12 = 5;
  while( true ) {
    uVar11 = 0;
    bVar5 = false;
    while (((int)uVar11 < 8 && (!bVar5))) {
      fVar6 = FLOAT_803debb4 + fVar1;
      if ((uVar11 & 1) != 0) {
        fVar6 = fVar1;
      }
      fVar7 = FLOAT_803debb4 + fVar2;
      if ((uVar11 & 2) != 0) {
        fVar7 = fVar2;
      }
      fVar8 = fVar4;
      if ((uVar11 & 4) != 0) {
        fVar8 = fVar3;
      }
      if (FLOAT_803debcc < fVar6 * *pfVar9 + fVar7 * pfVar9[2] + fVar8 * pfVar9[1] + pfVar9[3]) {
        bVar5 = true;
      }
      uVar11 = uVar11 + 1;
    }
    if ((uVar11 == 8) && (!bVar5)) break;
    pfVar9 = pfVar9 + 5;
    iVar12 = iVar12 + -1;
    if (iVar12 == 0) {
      uVar10 = 1;
LAB_8005a894:
      __psq_l0(auStack8,0);
      __psq_l1(auStack8,0);
      return uVar10;
    }
  }
  uVar10 = 0;
  goto LAB_8005a894;
}

