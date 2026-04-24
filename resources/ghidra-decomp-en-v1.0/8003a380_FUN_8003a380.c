// Function: FUN_8003a380
// Entry: 8003a380
// Size: 1332 bytes

/* WARNING: Removing unreachable block (ram,0x8003a88c) */
/* WARNING: Removing unreachable block (ram,0x8003a87c) */
/* WARNING: Removing unreachable block (ram,0x8003a884) */
/* WARNING: Removing unreachable block (ram,0x8003a894) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_8003a380(undefined4 param_1,undefined4 param_2,float *param_3,int param_4,short *param_5,
                 undefined4 param_6,short param_7)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  short *psVar4;
  short sVar6;
  short *psVar5;
  int iVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  uint *puVar13;
  short *psVar14;
  int iVar15;
  undefined4 uVar16;
  double extraout_f1;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  undefined8 uVar20;
  short local_88 [4];
  undefined4 local_80;
  uint uStack124;
  undefined8 local_78;
  double local_70;
  double local_68;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar20 = FUN_802860d0();
  psVar4 = (short *)((ulonglong)uVar20 >> 0x20);
  iVar15 = (int)uVar20;
  psVar12 = param_5 + 0xf;
  dVar19 = (double)(*param_3 - *(float *)(iVar15 + 0xc));
  dVar17 = (double)(param_3[2] - *(float *)(iVar15 + 0x14));
  dVar18 = (double)((float)((double)param_3[1] + extraout_f1) - *(float *)(iVar15 + 0x10));
  uVar20 = FUN_802931a0((double)(float)(dVar19 * dVar19 + (double)(float)(dVar17 * dVar17)));
  sVar6 = FUN_800217c0(dVar19,dVar17);
  local_88[2] = sVar6 - *psVar4;
  if (0x8000 < local_88[2]) {
    local_88[2] = local_88[2] + 1;
  }
  if (local_88[2] < -0x8000) {
    local_88[2] = local_88[2] - 1;
  }
  local_88[3] = FUN_800217c0(uVar20,dVar18);
  uVar3 = local_88[2];
  local_88[3] = param_7 + local_88[3];
  if (0x8000 < local_88[3]) {
    local_88[3] = local_88[3] + 1;
  }
  if (local_88[3] < -0x8000) {
    local_88[3] = local_88[3] + -1;
  }
  if ((char)DAT_803dcc00 < '\0') {
    local_88[2] = local_88[2] + 0x8000;
    local_88[3] = -local_88[3];
    DAT_803dcc00 = DAT_803dcc00 & 0x7f;
  }
  iVar15 = 0;
  puVar13 = &DAT_802cae88;
  while( true ) {
    psVar14 = (short *)0x0;
    iVar7 = *(int *)(psVar4 + 0x28);
    if (iVar7 != 0) {
      iVar9 = 0;
      iVar10 = 0;
      for (uVar2 = (uint)*(byte *)(iVar7 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
        if ((*(char *)(*(int *)(iVar7 + 0x10) + *(char *)((int)psVar4 + 0xad) + iVar9 + 1) != -1) &&
           (*puVar13 == (uint)*(byte *)(*(int *)(iVar7 + 0x10) + iVar9))) {
          psVar14 = (short *)(*(int *)(psVar4 + 0x36) + iVar10);
        }
        iVar9 = *(char *)(iVar7 + 0x55) + iVar9 + 1;
        iVar10 = iVar10 + 0x12;
      }
    }
    if (psVar14 == (short *)0x0) break;
    uVar2 = 0;
    psVar5 = local_88 + 2;
    psVar8 = local_88;
    iVar7 = 2;
    do {
      if ((uVar2 & 1 ^ uVar2 >> 0x1f) == uVar2 >> 0x1f) {
        local_70 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar9 = (int)(FLOAT_803de9ec * (float)(local_70 - DOUBLE_803de9d0));
        local_68 = (double)(longlong)iVar9;
        local_78._6_2_ = (short)iVar9;
      }
      else {
        uStack124 = (int)*psVar12 ^ 0x80000000U;
        local_80 = 0x43300000;
        iVar9 = (int)(FLOAT_803de9ec *
                     (float)((double)CONCAT44(0x43300000,(int)*psVar12 ^ 0x80000000U) -
                            DOUBLE_803de9d0));
        local_78 = (longlong)iVar9;
        local_78._6_2_ = (short)iVar9;
      }
      sVar6 = *psVar5;
      *psVar8 = sVar6;
      if ((int)local_78._6_2_ < (int)sVar6) {
        *psVar8 = local_78._6_2_;
        *psVar5 = sVar6 - local_78._6_2_;
      }
      else {
        iVar9 = -(int)local_78._6_2_;
        if (sVar6 < iVar9) {
          *psVar8 = (short)iVar9;
          *psVar5 = sVar6 + local_78._6_2_;
        }
        else {
          *psVar5 = 0;
        }
      }
      psVar5 = psVar5 + 1;
      psVar8 = psVar8 + 1;
      uVar2 = uVar2 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    if (param_4 == 0) {
      iVar9 = (int)(short)((short)((int)psVar14[1] + (int)local_88[0] >> 1) - psVar14[1]);
      uVar2 = (uint)DAT_803db410;
      local_68 = (double)CONCAT44(0x43300000,-(int)*param_5 ^ 0x80000000);
      iVar7 = uVar2 * ((int)(short)(int)(FLOAT_803de9ec * (float)(local_68 - DOUBLE_803de9d0)) /
                      DAT_803db460);
      if (iVar7 <= iVar9) {
        local_68 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar10 = uVar2 * ((int)(short)(int)(FLOAT_803de9ec * (float)(local_68 - DOUBLE_803de9d0)) /
                         DAT_803db460);
        iVar7 = iVar9;
        if (iVar10 < iVar9) {
          iVar7 = iVar10;
        }
      }
      iVar11 = (int)(short)((short)((int)*psVar14 + (int)local_88[1] >> 1) - *psVar14);
      local_68 = (double)CONCAT44(0x43300000,(int)*psVar12 ^ 0x80000000);
      iVar9 = (int)(FLOAT_803de9ec * (float)(local_68 - DOUBLE_803de9d0));
      local_70 = (double)(longlong)iVar9;
      iVar10 = (int)(short)iVar9;
      iVar9 = uVar2 * (-iVar10 / (DAT_803db460 << 1));
      if ((iVar9 <= iVar11) &&
         (iVar10 = uVar2 * (iVar10 / (DAT_803db460 << 1)), iVar9 = iVar11, iVar10 < iVar11)) {
        iVar9 = iVar10;
      }
      *psVar14 = *psVar14 + (short)iVar9;
      psVar14[1] = psVar14[1] + (short)iVar7;
    }
    else {
      *(short *)(param_4 + 0x14) = local_88[0];
      FUN_800399c0(param_4,psVar14);
      *(short *)(param_4 + 0x44) = local_88[1];
      FUN_80039834((double)FLOAT_803de9d8,(double)FLOAT_803de9dc,param_4 + 0x30,psVar14);
      param_4 = param_4 + 0x60;
    }
    if (iVar15 == 0) {
      uVar3 = uVar3 - psVar14[1];
    }
    puVar13 = puVar13 + 1;
    psVar12 = psVar12 + 1;
    param_5 = param_5 + 1;
    iVar15 = iVar15 + 1;
    uVar1 = local_88[2];
    if (9 < iVar15) {
LAB_8003a87c:
      __psq_l0(auStack8,uVar16);
      __psq_l1(auStack8,uVar16);
      __psq_l0(auStack24,uVar16);
      __psq_l1(auStack24,uVar16);
      __psq_l0(auStack40,uVar16);
      __psq_l1(auStack40,uVar16);
      __psq_l0(auStack56,uVar16);
      __psq_l1(auStack56,uVar16);
      FUN_8028611c((int)(short)uVar1);
      return;
    }
  }
  uVar2 = (uint)(short)uVar3;
  if ((int)uVar2 < 0) {
    uVar2 = -uVar2;
  }
  uVar1 = (ushort)(((int)(uVar2 ^ 0x100) >> 1) - ((uVar2 ^ 0x100) & 0x100) >> 0x1f);
  goto LAB_8003a87c;
}

