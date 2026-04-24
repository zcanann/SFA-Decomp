// Function: FUN_8003e2e0
// Entry: 8003e2e0
// Size: 684 bytes

void FUN_8003e2e0(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5,
                 uint param_6,uint param_7,uint param_8)

{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  uint uVar9;
  uint uVar10;
  undefined *puVar11;
  float *pfVar12;
  byte *pbVar13;
  byte *pbVar14;
  undefined8 uVar15;
  float afStack_68 [3];
  float local_5c;
  float local_4c;
  float local_3c;
  
  uVar15 = FUN_80286820();
  iVar7 = (int)((ulonglong)uVar15 >> 0x20);
  pbVar14 = &DAT_802cbaa8;
  iVar6 = FUN_80022b0c();
  if (DAT_803dd8c8 == 1) {
    if ((param_8 & 0xff) == 0) {
      FUN_8003bf30(iVar7,(int *)uVar15,param_5,param_4);
    }
    else {
      pfVar8 = (float *)FUN_80022b0c();
      bVar1 = *(byte *)(iVar7 + 0xf3);
      bVar2 = *(byte *)(iVar7 + 0xf4);
      pfVar12 = pfVar8 + 0x9c0;
      FUN_80022a88(0);
      for (iVar7 = 0; iVar7 < (int)((uint)bVar1 + (uint)bVar2); iVar7 = iVar7 + 1) {
        FUN_80247618(param_5,pfVar12,pfVar8);
        pfVar12 = pfVar12 + 0x10;
        pfVar8 = pfVar8 + 0xc;
      }
      DAT_803dd8c8 = 2;
    }
  }
  uVar10 = param_3[4];
  uVar5 = *(undefined *)(*param_3 + ((int)uVar10 >> 3));
  iVar7 = *param_3 + ((int)uVar10 >> 3);
  uVar3 = *(undefined *)(iVar7 + 1);
  uVar4 = *(undefined *)(iVar7 + 2);
  param_3[4] = uVar10 + 4;
  uVar10 = (uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar5)) >> (uVar10 & 7)) & 0xf;
  if (0x14 < uVar10) {
    FUN_8007d858();
  }
  pbVar13 = &DAT_802cbab4;
  for (iVar7 = 0; iVar7 < (int)uVar10; iVar7 = iVar7 + 1) {
    uVar9 = param_3[4];
    puVar11 = (undefined *)(*param_3 + ((int)uVar9 >> 3));
    uVar3 = *puVar11;
    uVar4 = puVar11[1];
    uVar5 = puVar11[2];
    param_3[4] = uVar9 + 8;
    uVar9 = (uint3)(CONCAT12(uVar5,CONCAT11(uVar4,uVar3)) >> (uVar9 & 7)) & 0xff;
    if (DAT_803dd8c8 == 2) {
      pfVar8 = (float *)(iVar6 + uVar9 * 0x30);
      pfVar12 = pfVar8 + 0x4b0;
      FUN_8025d80c(pfVar8,(uint)*pbVar14);
      if (((param_8 & 0xff) == 0) && ((param_7 & 0xff) != 0)) {
        FUN_8025d8c4(pfVar12,(uint)*pbVar13,0);
      }
      if (((param_8 & 0xff) == 0) && ((param_6 & 0xff) != 0)) {
        FUN_8025d848(pfVar12,(uint)*pbVar14);
      }
    }
    else {
      pfVar8 = (float *)FUN_80028630((int *)uVar15,uVar9);
      FUN_80247618(param_5,pfVar8,afStack_68);
      FUN_8025d80c(afStack_68,(uint)*pbVar14);
      if (((param_8 & 0xff) == 0) && (((param_6 & 0xff) != 0 || ((param_7 & 0xff) != 0)))) {
        local_5c = FLOAT_803df684;
        local_4c = FLOAT_803df684;
        local_3c = FLOAT_803df684;
        FUN_80247618(afStack_68,param_4,afStack_68);
        if ((param_7 & 0xff) != 0) {
          FUN_8025d8c4(afStack_68,(uint)*pbVar13,0);
        }
        if ((param_6 & 0xff) != 0) {
          FUN_8025d848(afStack_68,(uint)*pbVar14);
        }
      }
    }
    pbVar14 = pbVar14 + 1;
    pbVar13 = pbVar13 + 1;
  }
  FUN_8028686c();
  return;
}

