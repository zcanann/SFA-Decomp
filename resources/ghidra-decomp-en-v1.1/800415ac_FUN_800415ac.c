// Function: FUN_800415ac
// Entry: 800415ac
// Size: 572 bytes

void FUN_800415ac(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  undefined2 *puVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  
  puVar6 = FUN_8000facc();
  if (((((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0) && (*(char *)(param_1 + 0xac) != '?')) &&
      (*(short *)(param_1 + 0x46) != 0x882)) && (*(short *)(param_1 + 0x46) != 0x887)) {
    bVar5 = false;
    iVar9 = 3;
  }
  else {
    bVar5 = true;
    if (((*(short *)(param_1 + 0x44) == 1) || (sVar1 = *(short *)(param_1 + 0x46), sVar1 == 0x77d))
       || ((sVar1 == 0x882 || (sVar1 == 0x887)))) {
      iVar9 = 0xf;
    }
    else {
      iVar9 = 7;
    }
  }
  if (DAT_803dd8a4 == 0) {
    fVar2 = *(float *)(param_1 + 0x18) - *(float *)(puVar6 + 6);
    fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(puVar6 + 8);
    fVar4 = *(float *)(param_1 + 0x20) - *(float *)(puVar6 + 10);
  }
  else {
    fVar2 = *(float *)(DAT_803dd8a4 + 0xc) - (*(float *)(puVar6 + 6) - FLOAT_803dda58);
    fVar3 = *(float *)(DAT_803dd8a4 + 0x1c) - *(float *)(puVar6 + 8);
    fVar4 = *(float *)(DAT_803dd8a4 + 0x2c) - (*(float *)(puVar6 + 10) - FLOAT_803dda5c);
  }
  dVar11 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
  if (bVar5) {
    fVar2 = (float)((double)FLOAT_803df6e8 * dVar11) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dd8c0 = 1;
  }
  else {
    fVar2 = (FLOAT_803df6e4 * (float)((double)FLOAT_803df6e8 * dVar11)) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dd8c0 = 2;
  }
  iVar10 = 0x10 - (int)fVar2;
  if (0 < iVar10) {
    if (iVar9 < iVar10) {
      iVar10 = iVar9;
    }
    piVar7 = (int *)FUN_8002b660(param_1);
    iVar9 = DAT_803dd8a4;
    FUN_80028600((int)piVar7,FUN_8003cd14);
    for (DAT_803dd8c4 = 0; DAT_803dd8c4 < iVar10; DAT_803dd8c4 = DAT_803dd8c4 + 1) {
      iVar8 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar8 = *(int *)(param_1 + 0xc4);
      }
      FUN_800404b8(param_1,iVar8,*piVar7,4);
      DAT_803dd8a4 = iVar9;
    }
    DAT_803dd8a4 = 0;
    FUN_80028600((int)piVar7,0);
  }
  return;
}

