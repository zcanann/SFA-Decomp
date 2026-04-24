// Function: FUN_8029af9c
// Entry: 8029af9c
// Size: 1824 bytes

/* WARNING: Removing unreachable block (ram,0x8029b694) */
/* WARNING: Removing unreachable block (ram,0x8029b68c) */
/* WARNING: Removing unreachable block (ram,0x8029b69c) */

void FUN_8029af9c(void)

{
  float fVar1;
  float fVar2;
  undefined2 *puVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  ushort uVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  short local_78 [2];
  undefined auStack116 [6];
  undefined2 local_6e;
  float local_6c;
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [8];
  double local_58;
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar16 = FUN_802860d8();
  puVar3 = (undefined2 *)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  iVar10 = *(int *)(puVar3 + 0x5c);
  iVar4 = FUN_802ac7dc(puVar3,iVar6,iVar10);
  fVar1 = FLOAT_803e7ea4;
  if (iVar4 != 0) goto LAB_8029b68c;
  *(float *)(iVar6 + 0x294) = FLOAT_803e7ea4;
  *(float *)(iVar6 + 0x284) = fVar1;
  *(float *)(iVar6 + 0x280) = fVar1;
  *(float *)(puVar3 + 0x12) = fVar1;
  *(float *)(puVar3 + 0x14) = fVar1;
  *(float *)(puVar3 + 0x16) = fVar1;
  *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) | 0x2000000;
  FUN_8011f3ec(6);
  FUN_8011f3c8(10);
  if (puVar3[0x50] == 0x43e) {
    fVar1 = *(float *)(iVar6 + 0x28c) / FLOAT_803e7fa8;
    fVar2 = FLOAT_803e7ecc;
    if ((FLOAT_803e7ecc <= fVar1) && (fVar2 = fVar1, FLOAT_803e7ee0 < fVar1)) {
      fVar2 = FLOAT_803e7ee0;
    }
    dVar12 = (double)FUN_80021370((double)(fVar2 - *(float *)(iVar10 + 0x7bc)),
                                  (double)FLOAT_803e7efc,(double)FLOAT_803db414);
    *(float *)(iVar10 + 0x7bc) = (float)((double)*(float *)(iVar10 + 0x7bc) + dVar12);
    fVar1 = *(float *)(iVar6 + 0x290) / FLOAT_803e7fa8;
    fVar2 = FLOAT_803e7ecc;
    if ((FLOAT_803e7ecc <= fVar1) && (fVar2 = fVar1, FLOAT_803e7ee0 < fVar1)) {
      fVar2 = FLOAT_803e7ee0;
    }
    dVar12 = (double)FUN_80021370((double)(fVar2 - *(float *)(iVar10 + 0x7b8)),
                                  (double)FLOAT_803e7efc,(double)FLOAT_803db414);
    *(float *)(iVar10 + 0x7b8) = (float)((double)*(float *)(iVar10 + 0x7b8) + dVar12);
    dVar13 = (double)*(float *)(iVar10 + 0x7b8);
    dVar12 = (double)FLOAT_803e7ea4;
    if (dVar13 <= dVar12) {
      dVar15 = (double)(float)((double)FLOAT_803e7ea0 + dVar13);
      if (dVar12 < (double)(float)((double)FLOAT_803e7ea0 + dVar13)) {
        dVar15 = dVar12;
      }
    }
    else {
      dVar15 = (double)(float)(dVar13 - (double)FLOAT_803e7ea0);
      if ((double)(float)(dVar13 - (double)FLOAT_803e7ea0) < dVar12) {
        dVar15 = dVar12;
      }
    }
    fVar1 = *(float *)(iVar10 + 0x7bc);
    if (fVar1 <= FLOAT_803e7ea4) {
      local_58 = (double)(longlong)(int)(FLOAT_803e7fac * -fVar1);
      FUN_8002ed6c(puVar3,0x440,(int)(FLOAT_803e7fac * -fVar1));
    }
    else {
      local_58 = (double)(longlong)(int)(FLOAT_803e7fac * fVar1);
      FUN_8002ed6c(puVar3,0x441,(int)(FLOAT_803e7fac * fVar1));
    }
    iVar4 = (int)(FLOAT_803e7fb0 * *(float *)(iVar10 + 0x7b8));
    local_58 = (double)(longlong)iVar4;
    *(short *)(iVar10 + 0x4d2) = (short)iVar4;
    FUN_800395d8(puVar3,9);
    *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) & 0xfffffbff;
    if (DAT_803de4b2 == 0x2d) {
      dVar13 = (double)*(float *)(iVar10 + 0x7bc);
      dVar14 = (double)*(float *)(iVar10 + 0x7b8);
      uVar5 = FUN_8006fed4();
      dVar12 = DOUBLE_803e7ec0;
      fVar1 = FLOAT_803e7e98;
      uStack76 = (int)uVar5 >> 0x11;
      uVar5 = (int)(uVar5 & 0xffff) >> 1 ^ 0x80000000;
      local_58 = (double)CONCAT44(0x43300000,uVar5);
      *(float *)(iVar10 + 0x788) =
           FLOAT_803e7e98 * (float)(dVar14 * (double)(float)(local_58 - DOUBLE_803e7ec0)) +
           (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e7ec0);
      if ((double)FLOAT_803e7ea4 <= dVar13) {
        local_58 = (double)CONCAT44(0x43300000,uStack76 ^ 0x80000000);
        *(float *)(iVar10 + 0x78c) =
             FLOAT_803e7f44 *
             (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack76 ^ 0x80000000) -
                                             dVar12)) + (float)(local_58 - dVar12);
      }
      else {
        local_58 = (double)CONCAT44(0x43300000,uStack76 ^ 0x80000000);
        *(float *)(iVar10 + 0x78c) =
             fVar1 * (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,
                                                                       uStack76 ^ 0x80000000) -
                                                     dVar12)) + (float)(local_58 - dVar12);
      }
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) | 0x400;
    }
    if (DAT_803de42c == '\0') {
      if ((*(ushort *)(iVar10 + 0x6e2) & 0x900) != 0) {
        if ((*(ushort *)(iVar10 + 0x6e2) & 0x800) == 0) {
          iVar4 = 0;
          local_78[0] = DAT_803de4b2;
          uVar9 = 0x100;
        }
        else {
          iVar4 = FUN_8011f3a8(local_78);
          uVar9 = 0x800;
        }
        if (((*(ushort *)(iVar10 + 0x6e2) & 0x100) != 0) ||
           ((iVar4 == 1 && ((local_78[0] == 0x2d || (local_78[0] == 0x5ce)))))) {
          FUN_80014b3c(0,0x900);
          *(ushort *)(iVar10 + 0x6e2) = *(ushort *)(iVar10 + 0x6e2) & 0xf6ff;
          DAT_803de4b2 = local_78[0];
          if (local_78[0] != *(short *)(iVar10 + 0x80a)) {
            FUN_802ab38c(puVar3,iVar10);
          }
          if (DAT_803de4b2 == 0x5ce) {
            if (*(short *)(*(int *)(*(int *)(puVar3 + 0x5c) + 0x35c) + 4) < 1) {
              FUN_8000bb18(0,0x40c);
            }
            else {
              FUN_802a96d8(puVar3);
              DAT_803de42c = '\x01';
              FLOAT_803de430 = FLOAT_803e7ea4;
              DAT_803de4b4 = uVar9;
              *(float *)(iVar10 + 0x854) = FLOAT_803e7f58;
              iVar7 = *(int *)(*(int *)(puVar3 + 0x5c) + 0x35c);
              iVar4 = *(short *)(iVar7 + 4) + -1;
              if (iVar4 < 0) {
                iVar4 = 0;
              }
              else if (*(short *)(iVar7 + 6) < iVar4) {
                iVar4 = (int)*(short *)(iVar7 + 6);
              }
              *(short *)(iVar7 + 4) = (short)iVar4;
            }
          }
          else if (DAT_803de4b2 < 0x5ce) {
            if (DAT_803de4b2 == 0x2d) {
              if (1 < *(short *)(*(int *)(*(int *)(puVar3 + 0x5c) + 0x35c) + 4)) {
                *(code **)(iVar6 + 0x308) = FUN_8029a4a8;
                iVar4 = 0x2f;
                goto LAB_8029b68c;
              }
              FUN_8000bb18(0,0x40c);
            }
          }
          else if (DAT_803de4b2 == 0x958) {
            if (-1 < *(short *)(*(int *)(*(int *)(puVar3 + 0x5c) + 0x35c) + 4)) {
              *(code **)(iVar6 + 0x308) = FUN_8029a4a8;
              iVar4 = 0x30;
              goto LAB_8029b68c;
            }
            FUN_8000bb18(0,0x40c);
          }
        }
      }
    }
    else {
      FUN_8000da58(puVar3,0x382);
      fVar1 = *(float *)(iVar10 + 0x854) - FLOAT_803db414;
      *(float *)(iVar10 + 0x854) = fVar1;
      if (fVar1 <= FLOAT_803e7ea4) {
        iVar7 = *(int *)(*(int *)(puVar3 + 0x5c) + 0x35c);
        iVar4 = *(short *)(iVar7 + 4) + -1;
        if (iVar4 < 0) {
          iVar4 = 0;
        }
        else if (*(short *)(iVar7 + 6) < iVar4) {
          iVar4 = (int)*(short *)(iVar7 + 6);
        }
        *(short *)(iVar7 + 4) = (short)iVar4;
        *(float *)(iVar10 + 0x854) = FLOAT_803e7f58;
      }
      FUN_8003842c(DAT_803de44c,5,auStack104,auStack100,auStack96,0);
      local_6c = FLOAT_803e7f9c;
      local_6e = 0;
      (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack116,0x200001,0xffffffff,0);
      local_6e = 1;
      (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack116,0x200001,0xffffffff,0);
      if ((((*(ushort *)(iVar10 + 0x6e0) & DAT_803de4b4) == 0) ||
          (*(short *)(*(int *)(*(int *)(puVar3 + 0x5c) + 0x35c) + 4) == 0)) ||
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
    uStack76 = (int)*(short *)(iVar10 + 0x478) ^ 0x80000000;
    local_50 = 0x43300000;
    iVar4 = (int)((double)FLOAT_803e7fb4 * dVar15 +
                 (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0));
    local_58 = (double)(longlong)iVar4;
    *(short *)(iVar10 + 0x478) = (short)iVar4;
    *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    *puVar3 = *(undefined2 *)(iVar10 + 0x478);
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,puVar3,0x43e,0);
    *(float *)(iVar6 + 0x2a0) = FLOAT_803e7f34;
    DAT_803de42c = '\0';
    FLOAT_803de430 = FLOAT_803e7ea4;
  }
  if (((*(ushort *)(iVar10 + 0x6e2) & 0x200) == 0) && (*(char *)(iVar10 + 0x8c8) == 'R')) {
    iVar4 = 0;
  }
  else {
    *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) & 0xfdffffff;
    *(code **)(iVar6 + 0x308) = FUN_8029a420;
    iVar4 = 0x2c;
  }
LAB_8029b68c:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  FUN_80286124(iVar4);
  return;
}

