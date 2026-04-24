// Function: FUN_8005a8a4
// Entry: 8005a8a4
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x8005aa10) */
/* WARNING: Removing unreachable block (ram,0x8005a8ac) */

undefined4 FUN_8005a8a4(uint param_1,uint param_2,int param_3)

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
  uint uVar10;
  int iVar11;
  
  fVar1 = FLOAT_803df834 *
          (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803df840);
  fVar2 = FLOAT_803df834 *
          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803df840);
  fVar3 = FLOAT_803df86c;
  fVar4 = FLOAT_803df870;
  if (param_3 != 0) {
    fVar3 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8a) ^ 0x80000000) -
                   DOUBLE_803df840);
    fVar4 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8c) ^ 0x80000000) -
                   DOUBLE_803df840);
  }
  pfVar9 = (float *)&DAT_8038859c;
  iVar11 = 5;
  while( true ) {
    uVar10 = 0;
    bVar5 = false;
    while (((int)uVar10 < 8 && (!bVar5))) {
      fVar6 = FLOAT_803df834 + fVar1;
      if ((uVar10 & 1) != 0) {
        fVar6 = fVar1;
      }
      fVar7 = FLOAT_803df834 + fVar2;
      if ((uVar10 & 2) != 0) {
        fVar7 = fVar2;
      }
      fVar8 = fVar4;
      if ((uVar10 & 4) != 0) {
        fVar8 = fVar3;
      }
      if (FLOAT_803df84c < fVar6 * *pfVar9 + fVar7 * pfVar9[2] + fVar8 * pfVar9[1] + pfVar9[3]) {
        bVar5 = true;
      }
      uVar10 = uVar10 + 1;
    }
    if ((uVar10 == 8) && (!bVar5)) break;
    pfVar9 = pfVar9 + 5;
    iVar11 = iVar11 + -1;
    if (iVar11 == 0) {
      return 1;
    }
  }
  return 0;
}

