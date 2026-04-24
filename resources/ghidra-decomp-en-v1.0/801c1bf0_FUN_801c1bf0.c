// Function: FUN_801c1bf0
// Entry: 801c1bf0
// Size: 684 bytes

/* WARNING: Removing unreachable block (ram,0x801c1e70) */
/* WARNING: Removing unreachable block (ram,0x801c1e68) */
/* WARNING: Removing unreachable block (ram,0x801c1e78) */

undefined4 FUN_801c1bf0(int param_1)

{
  double dVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  if ((*(byte *)(*(int *)(param_1 + 0x4c) + 0x18) & 1) == 0) {
    iVar6 = **(int **)(param_1 + 0xb8);
    if (iVar6 == 0) goto LAB_801c1e68;
    piVar8 = *(int **)(iVar6 + 0xb8);
  }
  else {
    piVar8 = *(int **)(param_1 + 0xb8);
    iVar6 = param_1;
    param_1 = *piVar8;
  }
  if ((piVar8[0xb] != 0) && (param_1 != 0)) {
    dVar13 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar6 + 0xc));
    dVar12 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar6 + 0x10));
    dVar11 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar6 + 0x14));
    sVar4 = FUN_800217c0(dVar13,dVar11);
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *(short *)(piVar8 + 6) = sVar4;
    dVar10 = (double)FUN_802931a0((double)(float)(dVar11 * dVar11 +
                                                 (double)(float)(dVar13 * dVar13 +
                                                                (double)(float)(dVar12 * dVar12))));
    iVar5 = piVar8[0xb];
    dVar1 = (double)CONCAT44(0x43300000,*(byte *)(iVar5 + 8) - 1 ^ 0x80000000) - DOUBLE_803e4df0;
    iVar7 = *(int *)(iVar5 + 4);
    *(float *)(iVar5 + 0x38) = FLOAT_803e4e20;
    iVar5 = 0;
    while( true ) {
      iVar3 = *(byte *)((int *)piVar8[0xb] + 2) - 1;
      if (iVar3 <= iVar5) break;
      *(float *)(iVar7 + 0xc) = (float)(dVar10 / (double)(float)dVar1);
      iVar5 = iVar5 + 1;
      iVar7 = iVar7 + 0x24;
    }
    iVar3 = iVar3 * 0x34;
    *(float *)(*(int *)piVar8[0xb] + iVar3) = (float)dVar13;
    *(float *)(*(int *)piVar8[0xb] + iVar3 + 4) = (float)dVar12;
    *(float *)(*(int *)piVar8[0xb] + iVar3 + 8) = (float)dVar11;
    piVar8[1] = *(int *)(iVar6 + 0xc);
    piVar8[3] = *(int *)(iVar6 + 0x14);
    piVar8[2] = *(int *)(param_1 + 0xc);
    piVar8[4] = *(int *)(param_1 + 0x14);
    fVar2 = (float)piVar8[1];
    if ((float)piVar8[2] < fVar2) {
      piVar8[1] = piVar8[2];
      piVar8[2] = (int)fVar2;
    }
    fVar2 = (float)piVar8[3];
    if ((float)piVar8[4] < fVar2) {
      piVar8[3] = piVar8[4];
      piVar8[4] = (int)fVar2;
    }
    if ((float)piVar8[5] != FLOAT_803e4dfc) {
      fVar2 = (float)piVar8[5] - *(float *)(iVar6 + 0x10);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < (int)(*(byte *)((int *)piVar8[0xb] + 2) - 1); iVar5 = iVar5 + 1) {
        iVar7 = *(int *)piVar8[0xb];
        if (*(float *)(iVar7 + iVar6 + 4) < fVar2) {
          *(float *)(iVar7 + iVar6 + 4) = fVar2;
        }
        iVar6 = iVar6 + 0x34;
      }
    }
    fVar2 = FLOAT_803e4e24;
    piVar8[1] = (int)((float)piVar8[1] - FLOAT_803e4e24);
    piVar8[3] = (int)((float)piVar8[3] - fVar2);
    piVar8[2] = (int)((float)piVar8[2] + fVar2);
    piVar8[4] = (int)((float)piVar8[4] + fVar2);
  }
LAB_801c1e68:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  return 0;
}

