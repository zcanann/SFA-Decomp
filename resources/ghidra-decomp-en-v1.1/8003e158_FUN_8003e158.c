// Function: FUN_8003e158
// Entry: 8003e158
// Size: 392 bytes

void FUN_8003e158(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4)

{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  undefined uVar8;
  int iVar9;
  float *pfVar10;
  uint uVar11;
  uint uVar12;
  undefined *puVar13;
  float *pfVar14;
  int iVar15;
  byte *pbVar16;
  undefined8 uVar17;
  float afStack_58 [22];
  
  uVar17 = FUN_80286834();
  iVar15 = (int)((ulonglong)uVar17 >> 0x20);
  iVar9 = FUN_80022b0c();
  if (DAT_803dd8c8 == 1) {
    pfVar10 = (float *)FUN_80022b0c();
    bVar1 = *(byte *)(iVar15 + 0xf3);
    bVar2 = *(byte *)(iVar15 + 0xf4);
    pfVar14 = pfVar10 + 0x9c0;
    FUN_80022a88(0);
    for (iVar15 = 0; iVar15 < (int)((uint)bVar1 + (uint)bVar2); iVar15 = iVar15 + 1) {
      FUN_80247618(param_4,pfVar14,pfVar10);
      pfVar14 = pfVar14 + 0x10;
      pfVar10 = pfVar10 + 0xc;
    }
    DAT_803dd8c8 = 2;
  }
  uVar12 = param_3[4];
  uVar8 = *(undefined *)(*param_3 + ((int)uVar12 >> 3));
  iVar15 = *param_3 + ((int)uVar12 >> 3);
  uVar3 = *(undefined *)(iVar15 + 1);
  uVar4 = *(undefined *)(iVar15 + 2);
  param_3[4] = uVar12 + 4;
  pbVar16 = &DAT_802cbaa8;
  for (iVar15 = 0;
      iVar15 < (int)((uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar8)) >> (uVar12 & 7)) & 0xf);
      iVar15 = iVar15 + 1) {
    uVar11 = param_3[4];
    puVar13 = (undefined *)(*param_3 + ((int)uVar11 >> 3));
    uVar5 = *puVar13;
    uVar6 = puVar13[1];
    uVar7 = puVar13[2];
    param_3[4] = uVar11 + 8;
    uVar11 = (uint3)(CONCAT12(uVar7,CONCAT11(uVar6,uVar5)) >> (uVar11 & 7)) & 0xff;
    if (DAT_803dd8c8 == 2) {
      FUN_8025d80c((float *)(iVar9 + uVar11 * 0x30),(uint)*pbVar16);
    }
    else {
      pfVar10 = (float *)FUN_80028630((int *)uVar17,uVar11);
      FUN_80247618(param_4,pfVar10,afStack_58);
      FUN_8025d80c(afStack_58,(uint)*pbVar16);
    }
    pbVar16 = pbVar16 + 1;
  }
  FUN_80286880();
  return;
}

