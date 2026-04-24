// Function: FUN_800414b4
// Entry: 800414b4
// Size: 572 bytes

void FUN_800414b4(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  
  iVar6 = FUN_8000faac();
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
  if (DAT_803dcc24 == 0) {
    fVar2 = *(float *)(param_1 + 0x18) - *(float *)(iVar6 + 0xc);
    fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(iVar6 + 0x10);
    fVar4 = *(float *)(param_1 + 0x20) - *(float *)(iVar6 + 0x14);
  }
  else {
    fVar2 = *(float *)(DAT_803dcc24 + 0xc) - (*(float *)(iVar6 + 0xc) - FLOAT_803dcdd8);
    fVar3 = *(float *)(DAT_803dcc24 + 0x1c) - *(float *)(iVar6 + 0x10);
    fVar4 = *(float *)(DAT_803dcc24 + 0x2c) - (*(float *)(iVar6 + 0x14) - FLOAT_803dcddc);
  }
  dVar10 = (double)FUN_802931a0((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
  if (bVar5) {
    fVar2 = (float)((double)FLOAT_803dea68 * dVar10) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dcc40 = 1;
  }
  else {
    fVar2 = (FLOAT_803dea64 * (float)((double)FLOAT_803dea68 * dVar10)) /
            (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8));
    DAT_803dcc40 = 2;
  }
  iVar6 = 0x10 - (int)fVar2;
  if (0 < iVar6) {
    if (iVar9 < iVar6) {
      iVar6 = iVar9;
    }
    puVar7 = (undefined4 *)FUN_8002b588(param_1);
    iVar9 = DAT_803dcc24;
    FUN_8002853c(puVar7,FUN_8003cc1c);
    for (DAT_803dcc44 = 0; DAT_803dcc44 < iVar6; DAT_803dcc44 = DAT_803dcc44 + 1) {
      iVar8 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar8 = *(int *)(param_1 + 0xc4);
      }
      FUN_800403c0(param_1,iVar8,*puVar7,4);
      DAT_803dcc24 = iVar9;
    }
    DAT_803dcc24 = 0;
    FUN_8002853c(puVar7,0);
  }
  return;
}

