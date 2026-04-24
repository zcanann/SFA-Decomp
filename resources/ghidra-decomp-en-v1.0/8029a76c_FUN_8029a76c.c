// Function: FUN_8029a76c
// Entry: 8029a76c
// Size: 1132 bytes

/* WARNING: Removing unreachable block (ram,0x8029abb0) */
/* WARNING: Removing unreachable block (ram,0x8029abb8) */

void FUN_8029a76c(void)

{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined auStack120 [6];
  undefined2 local_72;
  float local_70;
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [12];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860d8();
  fVar1 = FLOAT_803e7ea4;
  iVar3 = (int)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  iVar9 = *(int *)(iVar3 + 0xb8);
  if (*(int *)(iVar6 + 0x2d0) == 0) {
    *(float *)(iVar6 + 0x294) = FLOAT_803e7ea4;
    *(float *)(iVar6 + 0x284) = fVar1;
    *(float *)(iVar6 + 0x280) = fVar1;
    *(float *)(iVar3 + 0x24) = fVar1;
    *(float *)(iVar3 + 0x28) = fVar1;
    *(float *)(iVar3 + 0x2c) = fVar1;
  }
  iVar4 = FUN_802ac7dc(iVar3,iVar6,iVar9);
  if (iVar4 == 0) {
    FUN_8011f3ec(6);
    FUN_8011f3c8(10);
    if (DAT_803de42c != '\0') {
      FUN_8000da58(iVar3,0x382);
      fVar1 = *(float *)(iVar9 + 0x854) - FLOAT_803db414;
      *(float *)(iVar9 + 0x854) = fVar1;
      if (fVar1 <= FLOAT_803e7ea4) {
        iVar7 = *(int *)(*(int *)(iVar3 + 0xb8) + 0x35c);
        iVar4 = *(short *)(iVar7 + 4) + -1;
        if (iVar4 < 0) {
          iVar4 = 0;
        }
        else if (*(short *)(iVar7 + 6) < iVar4) {
          iVar4 = (int)*(short *)(iVar7 + 6);
        }
        *(short *)(iVar7 + 4) = (short)iVar4;
        *(float *)(iVar9 + 0x854) = FLOAT_803e7f58;
      }
      FUN_8003842c(DAT_803de44c,5,auStack108,auStack104,auStack100,0);
      local_70 = FLOAT_803e7f9c;
      local_72 = 0;
      (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack120,0x200001,0xffffffff,0);
      local_72 = 1;
      (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack120,0x200001,0xffffffff,0);
      if ((((*(ushort *)(iVar9 + 0x6e0) & DAT_803de4b4) == 0) ||
          (*(short *)(*(int *)(*(int *)(iVar3 + 0xb8) + 0x35c) + 4) == 0)) ||
         (iVar4 = FUN_80080204(), iVar4 != 0)) {
        DAT_803de42c = '\0';
        iVar4 = 0;
        piVar8 = &DAT_80332ed4;
        do {
          if (*piVar8 != 0) {
            FUN_8002cbc4();
            *piVar8 = 0;
          }
          piVar8 = piVar8 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
        if (DAT_803de454 != 0) {
          FUN_80013e2c();
          DAT_803de454 = 0;
        }
      }
    }
    if (*(short *)(iVar3 + 0xa0) == 0x43f) {
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) & 0xfffffbff;
        dVar11 = (double)*(float *)(iVar9 + 0x7bc);
        dVar12 = (double)*(float *)(iVar9 + 0x7b8);
        uVar5 = FUN_8006fed4();
        dVar2 = DOUBLE_803e7ec0;
        fVar1 = FLOAT_803e7e98;
        uStack68 = (int)uVar5 >> 0x11;
        uVar5 = (int)(uVar5 & 0xffff) >> 1 ^ 0x80000000;
        *(float *)(iVar9 + 0x788) =
             FLOAT_803e7e98 *
             (float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e7ec0))
             + (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e7ec0);
        if ((double)FLOAT_803e7ea4 <= dVar11) {
          *(float *)(iVar9 + 0x78c) =
               FLOAT_803e7f44 *
               (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack68 ^ 0x80000000) -
                                               dVar2)) +
               (float)((double)CONCAT44(0x43300000,uStack68 ^ 0x80000000) - dVar2);
        }
        else {
          *(float *)(iVar9 + 0x78c) =
               fVar1 * (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,
                                                                         uStack68 ^ 0x80000000) -
                                                       dVar2)) +
               (float)((double)CONCAT44(0x43300000,uStack68 ^ 0x80000000) - dVar2);
        }
        uStack68 = uStack68 ^ 0x80000000;
        local_40 = 0x43300000;
        local_48 = 0x43300000;
        *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x400;
        uStack60 = uStack68;
        if (*(char *)(iVar6 + 0x346) != '\0') {
          *(code **)(iVar6 + 0x308) = FUN_8029a4a8;
          iVar4 = 0x2d;
          goto LAB_8029abb0;
        }
      }
    }
    else {
      FUN_8003842c(DAT_803de44c,0,auStack84,auStack80,auStack76,0);
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x3ed,auStack96,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
      iVar7 = *(int *)(*(int *)(iVar3 + 0xb8) + 0x35c);
      iVar4 = *(short *)(iVar7 + 4) + -2;
      if (iVar4 < 0) {
        iVar4 = 0;
      }
      else if (*(short *)(iVar7 + 6) < iVar4) {
        iVar4 = (int)*(short *)(iVar7 + 6);
      }
      *(short *)(iVar7 + 4) = (short)iVar4;
      FUN_802aa4b0((double)*(float *)(iVar9 + 0x7bc),iVar3,iVar6);
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        *(code **)(iVar6 + 0x308) = FUN_8029a4a8;
        iVar4 = 0x2d;
        goto LAB_8029abb0;
      }
      FLOAT_803de460 = FLOAT_803e7ea4;
      FLOAT_803de464 = FLOAT_803e7ea4;
    }
    if ((*(int *)(iVar6 + 0x2d0) == 0) &&
       (((*(ushort *)(iVar9 + 0x6e2) & 0x200) != 0 || (*(char *)(iVar9 + 0x8c8) != 'R')))) {
      *(code **)(iVar6 + 0x308) = FUN_8029a420;
      iVar4 = 0x2c;
    }
    else {
      iVar4 = 0;
    }
  }
LAB_8029abb0:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  FUN_80286124(iVar4);
  return;
}

