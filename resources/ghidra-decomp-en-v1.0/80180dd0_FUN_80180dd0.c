// Function: FUN_80180dd0
// Entry: 80180dd0
// Size: 1672 bytes

/* WARNING: Removing unreachable block (ram,0x80181430) */
/* WARNING: Removing unreachable block (ram,0x80180e48) */
/* WARNING: Removing unreachable block (ram,0x80181428) */
/* WARNING: Removing unreachable block (ram,0x80181438) */

void FUN_80180dd0(void)

{
  byte bVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  undefined4 local_68 [2];
  double local_60;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  psVar3 = (short *)FUN_802860d4();
  iVar12 = *(int *)(psVar3 + 0x5c);
  iVar11 = *(int *)(psVar3 + 0x26);
  iVar4 = FUN_8002b9ec();
  iVar10 = *(int *)(psVar3 + 0x26);
  local_68[0] = DAT_803e38e8;
  *(float *)(iVar12 + 0x11c) = *(float *)(iVar12 + 0x11c) + FLOAT_803db414;
  bVar1 = *(byte *)(iVar12 + 0x108);
  if (bVar1 == 2) {
LAB_80180f80:
    if (*(float *)(iVar12 + 0x11c) <= FLOAT_803e38ec) {
      iVar4 = (int)(FLOAT_803e38f4 * (*(float *)(iVar12 + 0x11c) / FLOAT_803e38ec));
      local_60 = (double)(longlong)iVar4;
      *(char *)(psVar3 + 0x1b) = (char)iVar4;
      goto LAB_80181428;
    }
    *(undefined *)(psVar3 + 0x1b) = 0xff;
    *(undefined *)(iVar12 + 0x108) = 3;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar11 + 0x20));
        fVar2 = FLOAT_803e38ec * (float)(local_60 - DOUBLE_803e3918);
        if (*(float *)(iVar12 + 0x11c) < fVar2) goto LAB_80181428;
        *(float *)(iVar12 + 0x11c) = *(float *)(iVar12 + 0x11c) - fVar2;
        *(undefined *)(iVar12 + 0x108) = 1;
      }
      *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar10 + 8);
      *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar10 + 0xc);
      *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar10 + 0x10);
      (**(code **)(*DAT_803dca9c + 0x14))
                ((double)*(float *)(psVar3 + 6),(double)*(float *)(psVar3 + 8),
                 (double)*(float *)(psVar3 + 10),local_68,1,0xffffffff);
      uVar5 = (**(code **)(*DAT_803dca9c + 0x1c))();
      (**(code **)(*DAT_803dca9c + 0x54))(uVar5,0);
      uVar6 = (**(code **)(*DAT_803dca9c + 0x1c))();
      (**(code **)(*DAT_803dca9c + 0x54))(uVar6,0);
      uVar7 = (**(code **)(*DAT_803dca9c + 0x1c))();
      iVar8 = FUN_800da980(iVar12,uVar5,uVar6,uVar7);
      if (iVar8 != 0) goto LAB_80181428;
      *(undefined *)(iVar12 + 0x108) = 2;
      *(float *)(iVar12 + 0x114) = FLOAT_803e38f0;
      goto LAB_80180f80;
    }
    if (3 < bVar1) goto LAB_80181428;
  }
  iVar8 = FUN_8003687c(psVar3,0,0,0);
  if (iVar8 == 0) {
    iVar8 = FUN_80296448(iVar4);
    if (iVar8 != 0) {
      dVar14 = (double)FUN_8002166c(iVar4 + 0xc,psVar3 + 6);
      fVar2 = FLOAT_803e38f8;
      uStack84 = (uint)*(byte *)(iVar11 + 0x23);
      local_60 = (double)CONCAT44(0x43300000,uStack84);
      local_58 = 0x43300000;
      if (dVar14 < (double)((float)(local_60 - DOUBLE_803e3918) *
                           (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e3918))) {
        uStack84 = (uint)*(byte *)(iVar10 + 0x19);
        local_58 = 0x43300000;
        *(float *)(iVar12 + 0x114) =
             *(float *)(iVar12 + 0x114) +
             (FLOAT_803e38f8 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e3918) *
             FLOAT_803db414) / FLOAT_803e38fc;
        fVar2 = fVar2 * *(float *)(iVar12 + 0x110);
        if (fVar2 < *(float *)(iVar12 + 0x114)) {
          *(float *)(iVar12 + 0x114) = fVar2;
        }
        goto LAB_80181110;
      }
    }
    uStack84 = FUN_800221a0(-(uint)*(byte *)(iVar10 + 0x19),(uint)*(byte *)(iVar10 + 0x19) << 1);
    uStack84 = uStack84 ^ 0x80000000;
    local_58 = 0x43300000;
    *(float *)(iVar12 + 0x114) =
         *(float *)(iVar12 + 0x114) +
         ((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e3920) * FLOAT_803db414) /
         FLOAT_803e38fc;
    if (FLOAT_803e38f0 <= *(float *)(iVar12 + 0x114)) {
      if (*(float *)(iVar12 + 0x110) < *(float *)(iVar12 + 0x114)) {
        *(float *)(iVar12 + 0x114) = *(float *)(iVar12 + 0x110);
      }
    }
    else {
      *(float *)(iVar12 + 0x114) = FLOAT_803e38f0;
    }
  }
  else {
    *(float *)(iVar12 + 0x114) = FLOAT_803e38f8 * *(float *)(iVar12 + 0x110);
  }
LAB_80181110:
  if (*(float *)(iVar12 + 0x110) * FLOAT_803e3900 <= *(float *)(iVar12 + 0x114)) {
    if (*(float *)(iVar12 + 0x114) <= FLOAT_803e390c * *(float *)(iVar12 + 0x110) * FLOAT_803e3900)
    {
      if ((psVar3[0x50] == 1) && (FLOAT_803e3910 < *(float *)(iVar12 + 0x10c))) {
        FUN_80030334((double)FLOAT_803e38f0,psVar3,0,0);
        FUN_8002f574(psVar3,0x3c);
        *(float *)(iVar12 + 0x10c) = FLOAT_803e38f0;
      }
      *(float *)(iVar12 + 0x118) =
           (FLOAT_803e3914 * *(float *)(iVar12 + 0x114)) / *(float *)(iVar12 + 0x110);
    }
    else {
      if ((psVar3[0x50] == 0) && (FLOAT_803e3910 < *(float *)(iVar12 + 0x10c))) {
        FUN_80030334((double)FLOAT_803e38f0,psVar3,1,0);
        FUN_8002f574(psVar3,0x3c);
        *(float *)(iVar12 + 0x10c) = FLOAT_803e38f0;
      }
      *(float *)(iVar12 + 0x118) = FLOAT_803e3914;
    }
  }
  else {
    if ((psVar3[0x50] == 0) && (FLOAT_803e3904 < *(float *)(iVar12 + 0x10c))) {
      FUN_80030334((double)FLOAT_803e38f0,psVar3,1,0);
      FUN_8002f574(psVar3,0x3c);
      *(float *)(iVar12 + 0x10c) = FLOAT_803e38f0;
    }
    *(float *)(iVar12 + 0x118) = FLOAT_803e3908;
  }
  if (FLOAT_803e38f0 != *(float *)(iVar12 + 0x114)) {
    fVar2 = *(float *)(iVar12 + 0x114) * FLOAT_803db414;
    dVar15 = (double)(fVar2 * fVar2);
    dVar14 = (double)FUN_8002166c(iVar12 + 0x68,psVar3 + 6);
    for (iVar4 = 0; (dVar14 < dVar15 && (iVar4 < 5)); iVar4 = iVar4 + 1) {
      FUN_80010320((double)FLOAT_803e38f8,iVar12);
      dVar14 = (double)FUN_8002166c(iVar12 + 0x68,psVar3 + 6);
    }
    if (*(int *)(iVar12 + 0x10) != 0) {
      (**(code **)(*DAT_803dca9c + 0x54))(*(undefined4 *)(iVar12 + 0xa4),0);
      uVar5 = (**(code **)(*DAT_803dca9c + 0x1c))();
      iVar4 = FUN_800da23c(iVar12,uVar5);
      if (iVar4 != 0) {
        *(undefined *)(iVar12 + 0x108) = 0;
        *(float *)(iVar12 + 0x11c) = FLOAT_803e38f0;
        *(undefined *)(psVar3 + 0x1b) = 0;
        goto LAB_80181428;
      }
    }
    dVar17 = (double)(*(float *)(iVar12 + 0x68) - *(float *)(psVar3 + 6));
    uStack84 = (uint)*(byte *)(iVar11 + 0x22);
    local_58 = 0x43300000;
    dVar16 = (double)((*(float *)(iVar12 + 0x6c) +
                      (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e3918)) -
                     *(float *)(psVar3 + 8));
    dVar15 = (double)(*(float *)(iVar12 + 0x70) - *(float *)(psVar3 + 10));
    dVar14 = (double)FUN_802931a0((double)(float)(dVar15 * dVar15 +
                                                 (double)(float)(dVar17 * dVar17 +
                                                                (double)(float)(dVar16 * dVar16))));
    *(float *)(psVar3 + 6) =
         (float)((double)(float)(dVar17 / dVar14) * (double)*(float *)(iVar12 + 0x114) +
                (double)*(float *)(psVar3 + 6));
    *(float *)(psVar3 + 8) =
         (float)(dVar16 / dVar14) * *(float *)(iVar12 + 0x114) + *(float *)(psVar3 + 8);
    *(float *)(psVar3 + 10) =
         (float)((double)(float)(dVar15 / dVar14) * (double)*(float *)(iVar12 + 0x114) +
                (double)*(float *)(psVar3 + 10));
    sVar9 = FUN_800217c0((double)(float)(dVar17 / dVar14),(double)(float)(dVar15 / dVar14));
    iVar4 = (int)sVar9 - ((int)*psVar3 & 0xffffU);
    if (0x8000 < iVar4) {
      iVar4 = iVar4 + -0xffff;
    }
    if (iVar4 < -0x8000) {
      iVar4 = iVar4 + 0xffff;
    }
    if (iVar4 < 0x181) {
      if (iVar4 < -0x180) {
        *psVar3 = *psVar3 + -0x180;
      }
      else {
        *psVar3 = sVar9;
      }
    }
    else {
      *psVar3 = *psVar3 + 0x180;
    }
  }
  FUN_8002fa48((double)*(float *)(iVar12 + 0x118),(double)FLOAT_803db414,psVar3,0);
  *(float *)(iVar12 + 0x10c) = *(float *)(iVar12 + 0x10c) + FLOAT_803db414;
LAB_80181428:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  __psq_l0(auStack40,uVar13);
  __psq_l1(auStack40,uVar13);
  FUN_80286120();
  return;
}

