// Function: FUN_800e5f1c
// Entry: 800e5f1c
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x800e6164) */
/* WARNING: Removing unreachable block (ram,0x800e6154) */
/* WARNING: Removing unreachable block (ram,0x800e615c) */
/* WARNING: Removing unreachable block (ram,0x800e616c) */

void FUN_800e5f1c(undefined4 param_1,int param_2)

{
  float fVar1;
  bool bVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  int local_58 [4];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  dVar10 = (double)FLOAT_803e06a4;
  dVar7 = (double)FLOAT_803e06a8;
  dVar8 = (double)FLOAT_803e0668;
  dVar9 = (double)FLOAT_803e068c;
  pfVar3 = (float *)FUN_800e6b38((double)*(float *)(param_2 + 8),(double)*(float *)(param_2 + 0x10),
                                 param_1,local_58,0);
  *(float *)(param_2 + 0x200) = (float)dVar10;
  *(float *)(param_2 + 0x1f0) = (float)dVar10;
  *(float *)(param_2 + 0x1d0) = (float)dVar7;
  *(float *)(param_2 + 0x1e0) = (float)dVar8;
  *(float *)(param_2 + 0x1c0) = (float)dVar8;
  *(float *)(param_2 + 0x210) = (float)dVar8;
  *(float *)(param_2 + 0x220) = (float)dVar9;
  *(float *)(param_2 + 0x230) = (float)dVar8;
  bVar2 = false;
  pfVar4 = pfVar3;
  for (iVar5 = 0; iVar5 < local_58[0]; iVar5 = iVar5 + 1) {
    if (*(char *)(pfVar4 + 5) != '\x0e') {
      if (((bVar2) || (FLOAT_803e06ac + *(float *)(param_2 + 0xc) <= *pfVar4)) ||
         (pfVar4[2] <= FLOAT_803e0678)) {
        if ((FLOAT_803e06ac + *(float *)(param_2 + 0xc) <= *pfVar4) && (pfVar4[2] < FLOAT_803e0668))
        {
          *(float *)(param_2 + 0x1d0) = *pfVar4;
        }
      }
      else {
        *(float *)(param_2 + 0x1f0) = *pfVar4;
        *(float *)(param_2 + 0x1c0) = *(float *)(param_2 + 0xc) - *pfVar4;
        if (*(char *)(param_2 + 0xb8) == -1) {
          *(undefined *)(param_2 + 0xb8) = *(undefined *)(pfVar4 + 5);
        }
        bVar2 = true;
      }
    }
    pfVar4 = pfVar4 + 6;
  }
  if (!bVar2) {
    *(float *)(param_2 + 0x1c0) = FLOAT_803e06b0;
  }
  if ((*(byte *)(param_2 + 0x260) & 0x10) != 0) {
    *(float *)(param_2 + 0x1c0) = FLOAT_803e0668;
  }
  for (iVar5 = 0; iVar5 < local_58[0]; iVar5 = iVar5 + 1) {
    if (((*(char *)(pfVar3 + 5) == '\x0e') && (FLOAT_803e06b4 < pfVar3[2])) &&
       ((fVar1 = *pfVar3, fVar1 < *(float *)(param_2 + 0x1d0) &&
        (*(float *)(param_2 + 0x1f0) < fVar1)))) {
      *(float *)(param_2 + 0x200) = fVar1;
      *(float *)(param_2 + 0x210) = pfVar3[1];
      *(float *)(param_2 + 0x220) = pfVar3[2];
      *(float *)(param_2 + 0x230) = pfVar3[3];
    }
    pfVar3 = pfVar3 + 6;
  }
  if (dVar10 != (double)*(float *)(param_2 + 0x200)) {
    *(float *)(param_2 + 0x1e0) =
         (float)((double)*(float *)(param_2 + 0x200) - (double)*(float *)(param_2 + 0xc));
  }
  *(undefined4 *)(param_2 + 0x1bc) = *(undefined4 *)(param_2 + 0x200);
  *(undefined4 *)(param_2 + 0x1b8) = *(undefined4 *)(param_2 + 0x1f0);
  *(undefined4 *)(param_2 + 0x1b0) = *(undefined4 *)(param_2 + 0x1d0);
  *(undefined4 *)(param_2 + 0x1b4) = *(undefined4 *)(param_2 + 0x1e0);
  *(undefined4 *)(param_2 + 0x1ac) = *(undefined4 *)(param_2 + 0x1c0);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  return;
}

