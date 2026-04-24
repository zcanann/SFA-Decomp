// Function: FUN_800e0134
// Entry: 800e0134
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x800e03c4) */
/* WARNING: Removing unreachable block (ram,0x800e03bc) */
/* WARNING: Removing unreachable block (ram,0x800e03cc) */

void FUN_800e0134(undefined4 param_1,undefined4 param_2,int param_3,int param_4,char param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar7;
  int iVar5;
  undefined4 uVar6;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int *piVar13;
  undefined4 uVar14;
  double dVar15;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar16;
  double dVar17;
  undefined8 uVar18;
  char local_d0 [4];
  undefined auStack204 [8];
  undefined auStack196 [8];
  undefined4 local_bc;
  float local_b8;
  undefined4 local_b4;
  undefined auStack176 [136];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar18 = FUN_802860c8();
  iVar4 = (int)((ulonglong)uVar18 >> 0x20);
  dVar16 = (double)FLOAT_803e063c;
  iVar10 = 0;
  iVar9 = 0;
  local_bc = *(undefined4 *)(iVar4 + 0xc);
  local_b8 = FLOAT_803e0640 + *(float *)(iVar4 + 0x10);
  local_b4 = *(undefined4 *)(iVar4 + 0x14);
  dVar17 = dVar16;
  FUN_80012d00(&local_bc,auStack204);
  piVar13 = &DAT_803a17e8;
  for (iVar12 = 0; iVar12 < DAT_803dd478; iVar12 = iVar12 + 1) {
    iVar11 = *piVar13;
    iVar8 = 0;
    do {
      if (((int)*(char *)(iVar11 + 0x19) == *(int *)((int)uVar18 + iVar8 * 4)) || (param_3 < 1)) {
        fVar1 = *(float *)(iVar11 + 8) - *(float *)(iVar4 + 0xc);
        fVar2 = *(float *)(iVar11 + 0xc) - *(float *)(iVar4 + 0x10);
        fVar3 = *(float *)(iVar11 + 0x10) - *(float *)(iVar4 + 0x14);
        dVar15 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar15 < dVar17) {
          local_bc = *(undefined4 *)(iVar11 + 8);
          local_b8 = FLOAT_803e0640 + *(float *)(iVar11 + 0xc);
          local_b4 = *(undefined4 *)(iVar11 + 0x10);
          FUN_80012d00(&local_bc,auStack196);
          cVar7 = FUN_800128dc(auStack196,auStack204,0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar7 != '\0')) &&
             (iVar8 = FUN_800640cc((double)FLOAT_803e0634,iVar4 + 0xc,&local_bc,0,auStack176,iVar4,
                                   (int)param_5,0xffffffff,0,0), iVar8 == 0)) {
            iVar10 = iVar11;
            dVar17 = dVar15;
          }
        }
        iVar8 = param_3;
        if ((*(char *)(iVar11 + 0x18) == param_4) && (dVar15 < dVar16)) {
          local_bc = *(undefined4 *)(iVar11 + 8);
          local_b8 = FLOAT_803e0640 + *(float *)(iVar11 + 0xc);
          local_b4 = *(undefined4 *)(iVar11 + 0x10);
          FUN_80012d00(&local_bc,auStack196);
          cVar7 = FUN_800128dc(auStack196,auStack204,0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar7 != '\0')) &&
             (iVar5 = FUN_800640cc((double)FLOAT_803e0634,iVar4 + 0xc,&local_bc,0,auStack176,iVar4,
                                   (int)param_5,0xffffffff,0,0), iVar5 == 0)) {
            iVar9 = iVar11;
            dVar16 = dVar15;
          }
        }
      }
      iVar8 = iVar8 + 1;
    } while (iVar8 < param_3);
    piVar13 = piVar13 + 1;
  }
  if (iVar9 != 0) {
    iVar10 = iVar9;
  }
  if (iVar10 == 0) {
    uVar6 = 0xffffffff;
  }
  else {
    uVar6 = *(undefined4 *)(iVar10 + 0x14);
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  FUN_80286114(uVar6);
  return;
}

