// Function: FUN_801d9bdc
// Entry: 801d9bdc
// Size: 1704 bytes

/* WARNING: Removing unreachable block (ram,0x801da25c) */
/* WARNING: Removing unreachable block (ram,0x801da24c) */
/* WARNING: Removing unreachable block (ram,0x801da244) */
/* WARNING: Removing unreachable block (ram,0x801da254) */
/* WARNING: Removing unreachable block (ram,0x801da264) */

void FUN_801d9bdc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  char *pcVar7;
  int iVar8;
  uint uVar9;
  char *pcVar10;
  int iVar11;
  undefined4 uVar12;
  undefined8 in_f27;
  double dVar13;
  undefined8 in_f28;
  double dVar14;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  undefined8 uVar18;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  undefined auStack224 [48];
  undefined auStack176 [48];
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
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
  uVar18 = FUN_802860d0();
  iVar8 = (int)((ulonglong)uVar18 >> 0x20);
  pcVar10 = *(char **)(iVar8 + 0xb8);
  uVar5 = FUN_8002b9ec();
  if (param_6 != '\0') {
    if (*pcVar10 == '\x03') {
      FUN_8002b47c(iVar8,auStack176,0);
      uVar6 = FUN_800383a0(uVar5,0);
      FUN_80246fd0(uVar6,auStack224);
      FUN_80246eb4(auStack224,auStack176,pcVar10 + 8);
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x04') {
      FUN_80038330(uVar5,0,pcVar10 + 8);
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x05') {
      uVar5 = FUN_800383a0(uVar5,0);
      FUN_80246eb4(uVar5,pcVar10 + 8,auStack176);
      FUN_800412d4(auStack176);
      FUN_80041ac4(iVar8);
    }
    else {
      FUN_8003b8f4((double)FLOAT_803e54d0,iVar8,(int)uVar18,param_3,param_4,param_5);
    }
    FUN_8003842c(iVar8,0,&local_ec,&local_e8,&local_e4,0);
    FUN_8003842c(iVar8,1,&local_f8,&local_f4,&local_f0,0);
    dVar17 = (double)(local_f8 - local_ec);
    dVar16 = (double)(local_f4 - local_e8);
    dVar15 = (double)(local_f0 - local_e4);
    if (((pcVar10[2] & 1U) != 0) && ((pcVar10[2] & 2U) == 0)) {
      iVar8 = 2;
      iVar11 = 4;
      pcVar7 = pcVar10;
      do {
        if (*(int *)(pcVar7 + 0x40) == 0) {
          pcVar10[iVar8 + 0x60] = '\x01';
          break;
        }
        iVar8 = iVar8 + 2;
        iVar11 = iVar11 + -1;
        pcVar7 = pcVar7 + 8;
      } while (iVar11 != 0);
      if (9 < iVar8) {
        pcVar10[2] = pcVar10[2] | 2;
      }
    }
    if (((pcVar10[2] & 4U) != 0) && ((pcVar10[2] & 8U) == 0)) {
      iVar8 = 1;
      pcVar7 = pcVar10 + 4;
      iVar11 = 5;
      do {
        if (*(int *)(pcVar7 + 0x38) == 0) {
          pcVar10[iVar8 + 0x60] = '\x01';
          break;
        }
        pcVar7 = pcVar7 + 8;
        iVar8 = iVar8 + 2;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      if (9 < iVar8) {
        pcVar10[2] = pcVar10[2] | 8;
      }
    }
    fVar3 = FLOAT_803e54f8;
    fVar2 = FLOAT_803e54d4;
    bVar1 = pcVar10[2];
    if (bVar1 == 0) {
      if (*(float *)(pcVar10 + 4) != FLOAT_803e54d4) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803db414;
        if (fVar2 < *(float *)(pcVar10 + 4)) {
          fVar3 = FLOAT_803e54e4 * *(float *)(pcVar10 + 4);
        }
        else {
          iVar8 = *(int *)(pcVar10 + 0x38);
          if (iVar8 != 0) {
            *(ushort *)(iVar8 + 6) = *(ushort *)(iVar8 + 6) | 0x4000;
            *(undefined4 *)(pcVar10 + 0x38) = 0;
            *(float *)(pcVar10 + 4) = fVar2;
          }
        }
      }
      if (*(int *)(pcVar10 + 0x38) != 0) {
        *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) =
             (float)(dVar17 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_ec);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) =
             (float)(dVar16 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e8);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) =
             (float)(dVar15 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e4);
        *(float *)(*(int *)(pcVar10 + 0x38) + 8) = fVar3;
      }
    }
    else if ((bVar1 & 0x20) == 0) {
      dVar14 = (double)FLOAT_803e54d8;
      if ((bVar1 & 0x10) != 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803db414;
        if (FLOAT_803e54d4 < *(float *)(pcVar10 + 4)) {
          dVar14 = (double)(FLOAT_803e54e4 * *(float *)(pcVar10 + 4));
        }
        else {
          pcVar10[2] = pcVar10[2] & 0xef;
        }
      }
      uVar9 = 0;
      do {
        if (*(int *)(pcVar10 + 0x38) != 0) {
          uStack124 = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          dVar13 = (double)(FLOAT_803e54f0 *
                           (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e5500));
          uStack116 = FUN_800221a0(0xffffffce,0x32);
          uStack116 = uStack116 ^ 0x80000000;
          local_78 = 0x43300000;
          dVar13 = (double)(float)(dVar13 + (double)((float)((double)CONCAT44(0x43300000,uStack116)
                                                            - DOUBLE_803e5500) / FLOAT_803e54f4));
          *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) = (float)(dVar17 * dVar13 + (double)local_ec);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) = (float)(dVar16 * dVar13 + (double)local_e8);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) = (float)(dVar15 * dVar13 + (double)local_e4);
          *(float *)(*(int *)(pcVar10 + 0x38) + 8) = (float)dVar14;
        }
        pcVar10 = pcVar10 + 4;
        uVar9 = uVar9 + 1;
      } while ((int)uVar9 < 10);
    }
    else {
      pcVar7 = pcVar10 + 0x14;
      for (iVar8 = 5; iVar8 < 5; iVar8 = iVar8 + 1) {
        iVar11 = *(int *)(pcVar7 + 0x38);
        if (iVar11 != 0) {
          *(ushort *)(iVar11 + 6) = *(ushort *)(iVar11 + 6) | 0x4000;
          *(undefined4 *)(pcVar7 + 0x38) = 0;
        }
        pcVar7 = pcVar7 + 4;
      }
      if ((pcVar10[2] & 0x10U) == 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) + FLOAT_803db414;
        if (FLOAT_803e54e0 <= *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = FLOAT_803e54e0;
        }
        fVar3 = FLOAT_803e54e4 * *(float *)(pcVar10 + 4);
      }
      else {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803db414;
        fVar3 = FLOAT_803e54d8;
        if (FLOAT_803e54d4 < *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803db414;
          fVar3 = FLOAT_803e54dc * *(float *)(pcVar10 + 4);
        }
      }
      uVar9 = 0;
      iVar8 = 5;
      pcVar7 = pcVar10;
      do {
        if ((*(int *)(pcVar7 + 0x38) != 0) && (*(int *)(pcVar10 + 0x48) != 0)) {
          uStack124 = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e54e8 +
                  (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e5500) / FLOAT_803e54ec
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x48) + 0xc);
          *(float *)(*(int *)(pcVar7 + 0x38) + 0xc) = fVar4 * (local_ec - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar7 + 0x38) + 0x10) =
               fVar4 * (local_e8 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x10);
          *(float *)(*(int *)(pcVar7 + 0x38) + 0x14) =
               fVar4 * (local_e4 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x14);
          *(float *)(*(int *)(pcVar7 + 0x38) + 8) = fVar3;
        }
        pcVar7 = pcVar7 + 4;
        uVar9 = uVar9 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
      iVar8 = 9;
      pcVar7 = pcVar10 + 0x24;
      iVar11 = 5;
      do {
        if ((*(int *)(pcVar7 + 0x38) != 0) && (*(int *)(pcVar10 + 0x4c) != 0)) {
          uStack124 = 9U - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e54e8 +
                  (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e5500) / FLOAT_803e54ec
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x4c) + 0xc);
          *(float *)(*(int *)(pcVar7 + 0x38) + 0xc) = fVar4 * (local_f8 - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar7 + 0x38) + 0x10) =
               fVar4 * (local_f4 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10);
          *(float *)(*(int *)(pcVar7 + 0x38) + 0x14) =
               fVar4 * (local_f0 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14);
          *(float *)(*(int *)(pcVar7 + 0x38) + 8) = fVar3;
        }
        pcVar7 = pcVar7 + -4;
        iVar8 = iVar8 + -1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  __psq_l0(auStack72,uVar12);
  __psq_l1(auStack72,uVar12);
  FUN_8028611c();
  return;
}

