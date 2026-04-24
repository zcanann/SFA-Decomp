// Function: FUN_80109a14
// Entry: 80109a14
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x80109d20) */
/* WARNING: Removing unreachable block (ram,0x80109d18) */
/* WARNING: Removing unreachable block (ram,0x80109d10) */
/* WARNING: Removing unreachable block (ram,0x80109a34) */
/* WARNING: Removing unreachable block (ram,0x80109a2c) */
/* WARNING: Removing unreachable block (ram,0x80109a24) */

void FUN_80109a14(short *param_1)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  char cVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  dVar10 = (double)FLOAT_803e24c0;
  iVar6 = *(int *)(param_1 + 0x52);
  uVar2 = FUN_80014f14(0);
  uVar3 = FUN_80014e9c(0);
  if ((uVar3 & 2) == 0) {
    if ((uVar2 & 8) != 0) {
      dVar10 = (double)(FLOAT_803e24c4 * *DAT_803de1c8);
    }
    if ((uVar2 & 4) != 0) {
      dVar10 = (double)(FLOAT_803e24c8 * *DAT_803de1c8);
    }
    dVar7 = dVar10;
    if (dVar10 < (double)FLOAT_803e24c0) {
      dVar7 = -dVar10;
    }
    dVar9 = (double)DAT_803de1c8[1];
    dVar8 = dVar9;
    if (dVar9 < (double)FLOAT_803e24c0) {
      dVar8 = -dVar9;
    }
    fVar1 = FLOAT_803e24d0;
    if (dVar7 < dVar8) {
      fVar1 = FLOAT_803e24cc;
    }
    DAT_803de1c8[1] = fVar1 * (float)(dVar10 - dVar9) + DAT_803de1c8[1];
    *DAT_803de1c8 = *DAT_803de1c8 + DAT_803de1c8[1];
    if (*DAT_803de1c8 < FLOAT_803e24d4) {
      *DAT_803de1c8 = FLOAT_803e24d4;
    }
    if (FLOAT_803e24d8 < *DAT_803de1c8) {
      *DAT_803de1c8 = FLOAT_803e24d8;
    }
    cVar4 = FUN_80014c44(0);
    cVar5 = FUN_80014bf0(0);
    *param_1 = *param_1 + cVar4 * -3;
    param_1[1] = param_1[1] + cVar5 * 3;
    dVar10 = (double)FUN_802945e0();
    dVar7 = (double)FUN_80294964();
    dVar8 = (double)FUN_80294964();
    dVar9 = (double)FUN_802945e0();
    fVar1 = *DAT_803de1c8;
    dVar8 = (double)(float)((double)fVar1 * dVar8);
    *(float *)(param_1 + 0xc) = *(float *)(iVar6 + 0x18) + (float)(dVar8 * dVar7);
    *(float *)(param_1 + 0xe) =
         FLOAT_803e24d4 + *(float *)(iVar6 + 0x1c) + (float)((double)fVar1 * dVar9);
    *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + (float)(dVar8 * dVar10);
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

