// Function: FUN_801816f8
// Entry: 801816f8
// Size: 2820 bytes

/* WARNING: Removing unreachable block (ram,0x801821d4) */
/* WARNING: Removing unreachable block (ram,0x801821dc) */

void FUN_801816f8(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  char cVar8;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined uVar9;
  short *psVar5;
  short sVar7;
  int iVar6;
  int iVar10;
  byte bVar11;
  bool bVar12;
  undefined4 uVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar16 = FUN_802860d8();
  iVar10 = (int)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  if (*(short *)(param_3 + 0x1c) != -1) {
    FUN_800200e8((int)*(short *)(param_3 + 0x1c),1);
  }
  cVar8 = FUN_8002e04c();
  if (cVar8 == '\0') {
    uVar2 = 0;
  }
  else {
    bVar12 = DAT_803ac794 < FLOAT_803e393c;
    bVar11 = *(byte *)(param_3 + 0x1e);
    if (bVar11 == 7) {
      uStack76 = FUN_80296ae8(iVar6);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968);
      uVar3 = FUN_80296ad4(iVar6);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      dVar14 = (double)(float)(local_48 - DOUBLE_803e3968);
      fVar1 = (float)(dVar15 / dVar14) * FLOAT_803e3930;
      if (FLOAT_803e3940 < fVar1) {
        if (FLOAT_803e3944 < fVar1) {
          uVar2 = 1;
          goto LAB_801821d4;
        }
        local_48 = (double)(longlong)(int)(fVar1 - FLOAT_803e3940);
        iVar4 = FUN_800221a0(0,(int)(short)(int)(fVar1 - FLOAT_803e3940));
        if (iVar4 < 7) {
          bVar11 = 6;
          local_48 = (double)(longlong)(int)(dVar14 * (double)FLOAT_803e393c);
          iVar4 = (int)(short)(int)(dVar14 * (double)FLOAT_803e393c);
          if (iVar4 < 1) {
            iVar4 = 1;
          }
          FUN_800221a0(1,iVar4);
        }
        else {
          bVar11 = 1;
          FUN_800221a0(1,4);
        }
      }
      else {
        bVar11 = 6;
      }
    }
    if (bVar11 == 3) {
      iVar4 = FUN_8002bdf4(0x24,0x3d5);
      uVar9 = FUN_800221a0(0xffffff81,0x7e);
      *(undefined *)(iVar4 + 0x18) = uVar9;
      *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar10 + 0xc);
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar10 + 0x10);
      *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar10 + 0x14);
      *(undefined2 *)(iVar4 + 0x1a) = 2000;
      psVar5 = (short *)FUN_8002df90(iVar4,5,(int)*(char *)(iVar10 + 0xac),0xffffffff,
                                     *(undefined4 *)(iVar10 + 0x30));
      fVar1 = FLOAT_803e3948;
      if (bVar12) {
        *(float *)(psVar5 + 0x12) = FLOAT_803e3948 * DAT_803ac790;
        *(float *)(psVar5 + 0x14) = FLOAT_803e394c * DAT_803ac794;
        *(float *)(psVar5 + 0x16) = fVar1 * DAT_803ac798;
      }
      else {
        *(float *)(psVar5 + 0x12) = *(float *)(iVar10 + 0xc) - *(float *)(iVar6 + 0xc);
        *(float *)(psVar5 + 0x16) = *(float *)(iVar10 + 0x14) - *(float *)(iVar6 + 0x14);
      }
      if (*(float *)(psVar5 + 0x12) * *(float *)(psVar5 + 0x12) +
          *(float *)(psVar5 + 0x16) * *(float *)(psVar5 + 0x16) != FLOAT_803e3938) {
        dVar14 = (double)FUN_802931a0();
        *(float *)(psVar5 + 0x12) = (float)((double)*(float *)(psVar5 + 0x12) / dVar14);
        *(float *)(psVar5 + 0x16) = (float)((double)*(float *)(psVar5 + 0x16) / dVar14);
      }
      uVar3 = FUN_800221a0(0,0x19);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      *(float *)(psVar5 + 0x12) =
           *(float *)(psVar5 + 0x12) *
           -(FLOAT_803e3954 * (float)(local_48 - DOUBLE_803e3968) - FLOAT_803e3950);
      uStack76 = FUN_800221a0(0,0x19);
      local_60 = FLOAT_803e3950;
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      *(float *)(psVar5 + 0x16) =
           *(float *)(psVar5 + 0x16) *
           -(FLOAT_803e3954 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968) -
            FLOAT_803e3950);
      *(float *)(psVar5 + 0x14) = FLOAT_803e3958;
      local_5c = FLOAT_803e3938;
      local_58 = FLOAT_803e3938;
      local_54 = FLOAT_803e3938;
      local_64 = 0;
      local_66 = 0;
      local_68 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_68,psVar5 + 0x12);
      sVar7 = FUN_800217c0((double)*(float *)(psVar5 + 0x12),-(double)*(float *)(psVar5 + 0x16));
      iVar10 = (int)*psVar5 - ((int)sVar7 & 0xffffU);
      if (0x8000 < iVar10) {
        iVar10 = iVar10 + -0xffff;
      }
      if (iVar10 < -0x8000) {
        iVar10 = iVar10 + 0xffff;
      }
      *psVar5 = (short)iVar10;
    }
    else if (bVar11 < 3) {
      if (bVar11 == 1) {
        iVar4 = FUN_8002bdf4(0x24,0x3d3);
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar10 + 0xc);
        *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar10 + 0x10);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar10 + 0x14);
        *(undefined2 *)(iVar4 + 0x1a) = 400;
        psVar5 = (short *)FUN_8002df90(iVar4,5,(int)*(char *)(iVar10 + 0xac),0xffffffff,
                                       *(undefined4 *)(iVar10 + 0x30));
        fVar1 = FLOAT_803e3948;
        if (bVar12) {
          *(float *)(psVar5 + 0x12) = FLOAT_803e3948 * DAT_803ac790;
          *(float *)(psVar5 + 0x14) = FLOAT_803e394c * DAT_803ac794;
          *(float *)(psVar5 + 0x16) = fVar1 * DAT_803ac798;
        }
        else {
          *(float *)(psVar5 + 0x12) = *(float *)(iVar10 + 0xc) - *(float *)(iVar6 + 0xc);
          *(float *)(psVar5 + 0x16) = *(float *)(iVar10 + 0x14) - *(float *)(iVar6 + 0x14);
        }
        if (*(float *)(psVar5 + 0x12) * *(float *)(psVar5 + 0x12) +
            *(float *)(psVar5 + 0x16) * *(float *)(psVar5 + 0x16) != FLOAT_803e3938) {
          dVar14 = (double)FUN_802931a0();
          *(float *)(psVar5 + 0x12) = (float)((double)*(float *)(psVar5 + 0x12) / dVar14);
          *(float *)(psVar5 + 0x16) = (float)((double)*(float *)(psVar5 + 0x16) / dVar14);
        }
        uVar3 = FUN_800221a0(0,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        *(float *)(psVar5 + 0x12) =
             *(float *)(psVar5 + 0x12) *
             -(FLOAT_803e3954 * (float)(local_48 - DOUBLE_803e3968) - FLOAT_803e3950);
        uStack76 = FUN_800221a0(0,0x19);
        local_60 = FLOAT_803e3950;
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        *(float *)(psVar5 + 0x16) =
             *(float *)(psVar5 + 0x16) *
             -(FLOAT_803e3954 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968) -
              FLOAT_803e3950);
        *(float *)(psVar5 + 0x14) = FLOAT_803e3958;
        local_5c = FLOAT_803e3938;
        local_58 = FLOAT_803e3938;
        local_54 = FLOAT_803e3938;
        local_64 = 0;
        local_66 = 0;
        local_68 = FUN_800221a0(0xffffd8f0,10000);
        FUN_80021ac8(&local_68,psVar5 + 0x12);
        sVar7 = FUN_800217c0((double)*(float *)(psVar5 + 0x12),-(double)*(float *)(psVar5 + 0x16));
        iVar10 = (int)*psVar5 - ((int)sVar7 & 0xffffU);
        if (0x8000 < iVar10) {
          iVar10 = iVar10 + -0xffff;
        }
        if (iVar10 < -0x8000) {
          iVar10 = iVar10 + 0xffff;
        }
        *psVar5 = (short)iVar10;
      }
      else if (bVar11 != 0) {
        iVar4 = FUN_8002bdf4(0x24,0x3d4);
        uVar9 = FUN_800221a0(0xffffff81,0x7e);
        *(undefined *)(iVar4 + 0x18) = uVar9;
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar10 + 0xc);
        *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar10 + 0x10);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar10 + 0x14);
        *(undefined2 *)(iVar4 + 0x1a) = 400;
        psVar5 = (short *)FUN_8002df90(iVar4,5,(int)*(char *)(iVar10 + 0xac),0xffffffff,
                                       *(undefined4 *)(iVar10 + 0x30));
        fVar1 = FLOAT_803e3948;
        if (bVar12) {
          *(float *)(psVar5 + 0x12) = FLOAT_803e3948 * DAT_803ac790;
          *(float *)(psVar5 + 0x14) = FLOAT_803e394c * DAT_803ac794;
          *(float *)(psVar5 + 0x16) = fVar1 * DAT_803ac798;
        }
        else {
          *(float *)(psVar5 + 0x12) = *(float *)(iVar10 + 0xc) - *(float *)(iVar6 + 0xc);
          *(float *)(psVar5 + 0x16) = *(float *)(iVar10 + 0x14) - *(float *)(iVar6 + 0x14);
        }
        if (*(float *)(psVar5 + 0x12) * *(float *)(psVar5 + 0x12) +
            *(float *)(psVar5 + 0x16) * *(float *)(psVar5 + 0x16) != FLOAT_803e3938) {
          dVar14 = (double)FUN_802931a0();
          *(float *)(psVar5 + 0x12) = (float)((double)*(float *)(psVar5 + 0x12) / dVar14);
          *(float *)(psVar5 + 0x16) = (float)((double)*(float *)(psVar5 + 0x16) / dVar14);
        }
        uVar3 = FUN_800221a0(0,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        *(float *)(psVar5 + 0x12) =
             *(float *)(psVar5 + 0x12) *
             -(FLOAT_803e3954 * (float)(local_48 - DOUBLE_803e3968) - FLOAT_803e3950);
        uStack76 = FUN_800221a0(0,0x19);
        local_60 = FLOAT_803e3950;
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        *(float *)(psVar5 + 0x16) =
             *(float *)(psVar5 + 0x16) *
             -(FLOAT_803e3954 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968) -
              FLOAT_803e3950);
        *(float *)(psVar5 + 0x14) = FLOAT_803e3958;
        local_5c = FLOAT_803e3938;
        local_58 = FLOAT_803e3938;
        local_54 = FLOAT_803e3938;
        local_64 = 0;
        local_66 = 0;
        local_68 = FUN_800221a0(0xffffd8f0,10000);
        FUN_80021ac8(&local_68,psVar5 + 0x12);
        sVar7 = FUN_800217c0((double)*(float *)(psVar5 + 0x12),-(double)*(float *)(psVar5 + 0x16));
        iVar10 = (int)*psVar5 - ((int)sVar7 & 0xffffU);
        if (0x8000 < iVar10) {
          iVar10 = iVar10 + -0xffff;
        }
        if (iVar10 < -0x8000) {
          iVar10 = iVar10 + 0xffff;
        }
        *psVar5 = (short)iVar10;
      }
    }
    else if ((bVar11 < 7) && (4 < bVar11)) {
      if (*(char *)(param_3 + 0x1e) == '\x05') {
        iVar6 = FUN_8002bdf4(0x30,0xb);
      }
      else {
        iVar6 = FUN_8002bdf4(0x30,0x3cd);
      }
      *(undefined *)(iVar6 + 0x1a) = 0x14;
      *(undefined2 *)(iVar6 + 0x2c) = 0xffff;
      *(undefined2 *)(iVar6 + 0x1c) = 0xffff;
      if (*(char *)(param_3 + 9) == '\0') {
        *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(iVar10 + 0xc);
        *(float *)(iVar6 + 0xc) = FLOAT_803e3960 + *(float *)(iVar10 + 0x10);
        *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar10 + 0x14);
      }
      else {
        uVar3 = FUN_800221a0(0xfffffff1,0xf);
        local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        *(float *)(iVar6 + 8) = *(float *)(iVar10 + 0xc) + (float)(local_48 - DOUBLE_803e3968);
        *(float *)(iVar6 + 0xc) = FLOAT_803e395c + *(float *)(iVar10 + 0x10);
        uStack76 = FUN_800221a0(0xfffffff1,0xf);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        *(float *)(iVar6 + 0x10) =
             *(float *)(iVar10 + 0x14) +
             (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968);
      }
      *(undefined2 *)(iVar6 + 0x24) = 0xffff;
      psVar5 = (short *)FUN_8002df90(iVar6,5,(int)*(char *)(iVar10 + 0xac),0xffffffff,
                                     *(undefined4 *)(iVar10 + 0x30));
      fVar1 = FLOAT_803e3948;
      if (bVar12) {
        *(float *)(psVar5 + 0x12) = FLOAT_803e3948 * DAT_803ac790;
        *(float *)(psVar5 + 0x14) = FLOAT_803e394c * DAT_803ac794;
        *(float *)(psVar5 + 0x16) = fVar1 * DAT_803ac798;
      }
      if (*(float *)(psVar5 + 0x12) * *(float *)(psVar5 + 0x12) +
          *(float *)(psVar5 + 0x16) * *(float *)(psVar5 + 0x16) != FLOAT_803e3938) {
        dVar15 = (double)FUN_802931a0();
        dVar14 = (double)FLOAT_803e3964;
        *(float *)(psVar5 + 0x12) = *(float *)(psVar5 + 0x12) / (float)(dVar14 * dVar15);
        *(float *)(psVar5 + 0x16) = *(float *)(psVar5 + 0x16) / (float)(dVar14 * dVar15);
      }
      uVar3 = FUN_800221a0(0,0x19);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      *(float *)(psVar5 + 0x12) =
           *(float *)(psVar5 + 0x12) *
           -(FLOAT_803e3954 * (float)(local_48 - DOUBLE_803e3968) - FLOAT_803e3950);
      uStack76 = FUN_800221a0(0,0x19);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      *(float *)(psVar5 + 0x16) =
           *(float *)(psVar5 + 0x16) *
           -(FLOAT_803e3954 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3968) -
            FLOAT_803e3950);
      *(float *)(psVar5 + 0x14) = FLOAT_803e3958;
      (**(code **)(**(int **)(psVar5 + 0x34) + 0x2c))
                ((double)*(float *)(psVar5 + 0x12),(double)*(float *)(psVar5 + 0x14),
                 (double)*(float *)(psVar5 + 0x16),psVar5);
      local_5c = FLOAT_803e3938;
      local_58 = FLOAT_803e3938;
      local_54 = FLOAT_803e3938;
      local_60 = FLOAT_803e3950;
      local_64 = 0;
      local_66 = 0;
      local_68 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_68,psVar5 + 0x12);
      sVar7 = FUN_800217c0((double)*(float *)(psVar5 + 0x12),-(double)*(float *)(psVar5 + 0x16));
      iVar10 = (int)*psVar5 - ((int)sVar7 & 0xffffU);
      if (0x8000 < iVar10) {
        iVar10 = iVar10 + -0xffff;
      }
      if (iVar10 < -0x8000) {
        iVar10 = iVar10 + 0xffff;
      }
      *psVar5 = (short)iVar10;
    }
    uVar2 = 1;
  }
LAB_801821d4:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  FUN_80286124(uVar2);
  return;
}

