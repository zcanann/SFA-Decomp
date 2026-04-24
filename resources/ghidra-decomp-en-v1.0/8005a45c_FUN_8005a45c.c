// Function: FUN_8005a45c
// Entry: 8005a45c
// Size: 716 bytes

void FUN_8005a45c(undefined4 param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double local_20;
  
  if (DAT_803dcded != '\0') {
    dVar9 = (double)FUN_80291e40((double)((*(float *)(DAT_803dcea8 + 0xc) - FLOAT_803dcdd8) /
                                         FLOAT_803debb4));
    iVar8 = (int)dVar9;
    dVar9 = (double)FUN_80291e40((double)((*(float *)(DAT_803dcea8 + 0x14) - FLOAT_803dcddc) /
                                         FLOAT_803debb4));
    iVar2 = (int)dVar9;
    if ((((iVar8 < 0) || (iVar2 < 0)) || (0xf < iVar8)) || (0xf < iVar2)) {
      iVar8 = 0;
    }
    else {
      iVar8 = (int)*(char *)(DAT_803822b4 + iVar8 + iVar2 * 0x10);
      if ((iVar8 < 0) || ((int)(uint)DAT_803dce98 <= iVar8)) {
        iVar8 = 0;
      }
      else {
        iVar8 = *(int *)(DAT_803dce9c + iVar8 * 4);
      }
    }
    dVar9 = (double)FUN_80291e40((double)(*(float *)(DAT_803dcea8 + 0xc) / FLOAT_803debb4));
    dVar11 = (double)FLOAT_803debb4;
    dVar10 = (double)FUN_80291e40((double)(float)((double)*(float *)(DAT_803dcea8 + 0x14) / dVar11))
    ;
    iVar2 = (int)(*(float *)(DAT_803dcea8 + 0xc) -
                 (float)((double)CONCAT44(0x43300000,(int)(dVar11 * dVar9) ^ 0x80000000) -
                        DOUBLE_803debc0));
    iVar3 = (int)(*(float *)(DAT_803dcea8 + 0x14) -
                 (float)((double)CONCAT44(0x43300000,
                                          (int)((double)FLOAT_803debb4 * dVar10) ^ 0x80000000) -
                        DOUBLE_803debc0));
    if (iVar8 != 0) {
      uVar6 = (uint)*(short *)(iVar8 + 0x8a);
      uVar7 = uVar6;
      if ((uVar6 & 1) != 0) {
        uVar7 = uVar6 - 1;
      }
      fVar1 = *(float *)(DAT_803dcea8 + 0x10);
      uVar4 = (uint)*(short *)(iVar8 + 0x8c);
      local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      if ((float)(local_20 - DOUBLE_803debc0) < fVar1) {
        fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 - 1 ^ 0x80000000) - DOUBLE_803debc0);
      }
      uVar4 = uVar4 - uVar6;
      iVar8 = (int)uVar4 / 0x50 + ((int)uVar4 >> 0x1f);
      if (iVar8 - (iVar8 >> 0x1f) < 8) {
        iVar8 = ((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0);
      }
      else {
        iVar8 = 0x50;
      }
      iVar2 = iVar2 / 0x50 + (iVar2 >> 0x1f);
      iVar3 = iVar3 / 0x50 + (iVar3 >> 0x1f);
      FUN_80137948(s__cellx__i_celly__i_cellz__i_8030e7a4);
      uVar6 = (uint)DAT_803dce70;
      iVar5 = (int)uVar6 >> 3;
      if ((uVar6 & 7) != 0) {
        iVar5 = iVar5 + 1;
      }
      FUN_80013a64(param_1,DAT_803dce74 +
                           iVar5 * (((int)((int)fVar1 - uVar7) / iVar8) * 0x40 +
                                    (iVar3 - (iVar3 >> 0x1f)) * 8 + (iVar2 - (iVar2 >> 0x1f))),uVar6
                   ,uVar6);
    }
  }
  return;
}

