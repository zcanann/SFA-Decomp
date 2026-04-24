// Function: FUN_801c1740
// Entry: 801c1740
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x801c1948) */
/* WARNING: Removing unreachable block (ram,0x801c1938) */
/* WARNING: Removing unreachable block (ram,0x801c1930) */
/* WARNING: Removing unreachable block (ram,0x801c1940) */
/* WARNING: Removing unreachable block (ram,0x801c1950) */

void FUN_801c1740(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,float *param_6,undefined *param_7)

{
  int iVar1;
  float *pfVar2;
  float *pfVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_88;
  float local_84;
  float local_80 [2];
  undefined4 local_78;
  uint uStack116;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar14 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar14 >> 0x20);
  pfVar2 = (float *)uVar14;
  piVar6 = *(int **)(iVar1 + 0xb8);
  if ((*(byte *)(*(int *)(iVar1 + 0x4c) + 0x18) & 1) == 0) {
    iVar1 = 0;
  }
  else if (*piVar6 == 0) {
    iVar1 = 0;
  }
  else if ((((extraout_f1 < (double)(float)piVar6[1]) || ((double)(float)piVar6[2] < extraout_f1))
           || (param_3 < (double)(float)piVar6[3])) || ((double)(float)piVar6[4] < param_3)) {
    iVar1 = 0;
  }
  else {
    *pfVar2 = FLOAT_803e4e1c;
    dVar11 = (double)(float)(extraout_f1 - (double)*(float *)(iVar1 + 0xc));
    dVar12 = (double)(float)(param_2 - (double)*(float *)(iVar1 + 0x10));
    dVar13 = (double)(float)(param_3 - (double)*(float *)(iVar1 + 0x14));
    iVar1 = 0;
    iVar5 = 0;
    dVar10 = (double)FLOAT_803e4dfc;
    for (uVar4 = 0; (int)uVar4 < (int)(*(byte *)(piVar6[0xb] + 8) - 1); uVar4 = uVar4 + 1) {
      local_80[0] = (float)dVar11;
      local_84 = (float)dVar12;
      local_88 = (float)dVar13;
      pfVar3 = (float *)(*(int *)piVar6[0xb] + iVar5);
      dVar8 = (double)FUN_801c1698((double)*pfVar3,(double)pfVar3[1],(double)pfVar3[2],
                                   (double)pfVar3[0xd],(double)pfVar3[0xe],(double)pfVar3[0xf],
                                   local_80,&local_84,&local_88);
      if (((dVar10 <= dVar8) && (dVar8 < (double)FLOAT_803e4e18)) &&
         (dVar9 = (double)FUN_802931a0((double)((float)((double)local_88 - dVar13) *
                                                (float)((double)local_88 - dVar13) +
                                               (float)((double)local_80[0] - dVar11) *
                                               (float)((double)local_80[0] - dVar11) +
                                               (float)((double)local_84 - dVar12) *
                                               (float)((double)local_84 - dVar12))),
         dVar9 < (double)*pfVar2)) {
        iVar1 = uVar4 + 1;
        *pfVar2 = (float)dVar9;
        uStack116 = uVar4 ^ 0x80000000;
        local_78 = 0x43300000;
        *param_6 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e4df0)
                          + dVar8);
      }
      iVar5 = iVar5 + 0x34;
    }
    if (iVar1 != 0) {
      if ((int)(uint)*(byte *)(piVar6[0xb] + 8) >> 1 < iVar1 + -1) {
        *param_7 = 1;
      }
      else {
        *param_7 = 0;
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  __psq_l0(auStack72,uVar7);
  __psq_l1(auStack72,uVar7);
  FUN_80286120(iVar1);
  return;
}

