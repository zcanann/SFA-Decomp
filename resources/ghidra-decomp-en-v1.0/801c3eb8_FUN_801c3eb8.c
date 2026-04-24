// Function: FUN_801c3eb8
// Entry: 801c3eb8
// Size: 1768 bytes

/* WARNING: Removing unreachable block (ram,0x801c4570) */
/* WARNING: Removing unreachable block (ram,0x801c4560) */
/* WARNING: Removing unreachable block (ram,0x801c4550) */
/* WARNING: Removing unreachable block (ram,0x801c4558) */
/* WARNING: Removing unreachable block (ram,0x801c4568) */
/* WARNING: Removing unreachable block (ram,0x801c4578) */

void FUN_801c3eb8(short *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f26;
  double dVar11;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  undefined8 in_f31;
  double local_88;
  double local_78;
  undefined auStack88 [16];
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  iVar6 = *(int *)(param_1 + 0x26);
  iVar5 = *(int *)(param_1 + 0x5c);
  *(ushort *)(iVar5 + 0x2c) = *(short *)(iVar5 + 0x2c) - (ushort)DAT_803db410;
  iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1e));
  if (iVar3 == 0) {
    if (*(short *)(iVar5 + 0x2c) < 0) {
      if (*(char *)(iVar5 + 0x25) == '\0') {
        *(undefined2 *)(iVar5 + 0x2c) = 400;
        FUN_8000bb18(param_1,0x78);
        *(float *)(iVar5 + 0x1c) = FLOAT_803e4ec0;
      }
      else {
        *(undefined2 *)(iVar5 + 0x2c) = 0x113;
      }
      *(undefined *)(iVar5 + 0x49) = 0;
    }
    else if (*(short *)(iVar5 + 0x2c) < *(short *)(iVar5 + 0x2e)) {
      if (*(char *)(iVar5 + 0x49) == '\0') {
        FUN_8000bb18(param_1,0x79);
        if (*(char *)(iVar5 + 0x25) == '\0') {
          FUN_8000bb18(param_1,0x77);
        }
        *(undefined *)(iVar5 + 0x49) = 1;
        if (DAT_803ddbb8 != (int *)0x0) {
          (**(code **)(*DAT_803ddbb8 + 4))(param_1,10,0,0x10004,0xffffffff,0);
        }
      }
      if (*(short *)(iVar5 + 0x2c) < 0x28) {
        FUN_8000b7bc(param_1,0x40);
        if ((FLOAT_803e4ec0 <= *(float *)(iVar5 + 0x1c)) && (*(char *)(iVar5 + 0x25) == '\0')) {
          *(float *)(iVar5 + 0x1c) = -(FLOAT_803e4ec4 * FLOAT_803db414 - *(float *)(iVar5 + 0x1c));
        }
      }
      else if (*(short *)(iVar5 + 0x2c) < 0x8c) {
        if ((*(char *)(iVar5 + 0x49) == '\x01') &&
           (*(undefined *)(iVar5 + 0x49) = 2, DAT_803ddbb8 != (int *)0x0)) {
          (**(code **)(*DAT_803ddbb8 + 4))(param_1,0xb,0,0x10004,0xffffffff,0);
        }
      }
      else if (*(float *)(iVar5 + 0x1c) <= FLOAT_803e4ec8) {
        *(float *)(iVar5 + 0x1c) = FLOAT_803e4ecc * FLOAT_803db414 + *(float *)(iVar5 + 0x1c);
      }
    }
  }
  if (*(char *)(iVar5 + 0x24) != '\0') {
    FUN_8000b888((double)FLOAT_803e4ed4,param_1,0x40,
                 (int)(FLOAT_803e4ed0 * *(float *)(iVar5 + 0x1c)));
  }
  local_88 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1a) ^ 0x80000000);
  dVar14 = (double)(float)(local_88 - DOUBLE_803e4f00);
  dVar13 = (double)(float)(dVar14 * dVar14);
  dVar8 = (double)FUN_80294204((double)((FLOAT_803e4ed8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e4f00)) / FLOAT_803e4edc));
  local_78 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  dVar9 = (double)FUN_80293e80((double)((FLOAT_803e4ed8 * (float)(local_78 - DOUBLE_803e4f00)) /
                                       FLOAT_803e4edc));
  dVar11 = -(double)(float)((double)*(float *)(param_1 + 6) * dVar8 +
                           (double)(float)((double)*(float *)(param_1 + 10) * dVar9));
  iVar3 = FUN_8002b9ec();
  *(byte *)(iVar5 + 0x27) = *(char *)(iVar5 + 0x27) - DAT_803db410;
  if (*(char *)(iVar5 + 0x27) < '\0') {
    *(undefined *)(iVar5 + 0x27) = 0;
  }
  if ((*(char *)(iVar5 + 0x4a) == '\x01') ||
     ((FLOAT_803e4ec0 <
       (float)(dVar11 + (double)(float)(dVar8 * (double)*(float *)(iVar3 + 0xc) +
                                       (double)(float)(dVar9 * (double)*(float *)(iVar3 + 0x14))))
      && (*(char *)(iVar5 + 0x4a) != '\0')))) {
    *(ushort *)(iVar5 + 0x2a) = *(short *)(iVar5 + 0x2a) - (ushort)DAT_803db410;
    if (*(short *)(iVar5 + 0x2a) < 0) {
      *(undefined2 *)(iVar5 + 0x2a) = 0;
      *(undefined *)(iVar5 + 0x25) = 0;
    }
  }
  else {
    *(ushort *)(iVar5 + 0x2a) = *(short *)(iVar5 + 0x2a) + (ushort)DAT_803db410;
    if (0x3c < *(short *)(iVar5 + 0x2a)) {
      *(undefined2 *)(iVar5 + 0x2a) = 0x3c;
      *(undefined *)(iVar5 + 0x25) = 1;
    }
  }
  if (*(char *)(iVar5 + 0x25) == '\0') {
    *(byte *)(iVar5 + 0x24) = *(byte *)(iVar5 + 0x49) & 3;
  }
  else {
    *(undefined *)(iVar5 + 0x24) = 1;
  }
  iVar6 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1e));
  if (iVar6 != 0) {
    *(undefined *)(iVar5 + 0x24) = 0;
  }
  if (*(char *)(iVar5 + 0x27) == '\0') {
    *(undefined2 *)(iVar5 + 0x28) = 0;
  }
  if (((iVar3 != 0) && (*(char *)(iVar5 + 0x27) == '\0')) && (*(char *)(iVar5 + 0x24) != '\0')) {
    local_78 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar5 + 0x26) ^ 0x80000000);
    dVar12 = (double)(FLOAT_803e4ee0 + (float)(local_78 - DOUBLE_803e4f00));
    dVar10 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 8));
    if ((dVar10 < dVar12) && (-(double)(float)((double)FLOAT_803e4ee4 + dVar12) < dVar10)) {
      fVar1 = (float)((double)*(float *)(iVar3 + 0xc) - (double)*(float *)(param_1 + 6));
      fVar2 = (float)((double)*(float *)(iVar3 + 0x14) - (double)*(float *)(param_1 + 10));
      if ((double)(fVar1 * fVar1 + fVar2 * fVar2) < dVar13) {
        dVar10 = (double)(float)(dVar11 + (double)(float)(dVar8 * (double)*(float *)(iVar3 + 0xc) +
                                                         (double)(float)(dVar9 * (double)*(float *)(
                                                  iVar3 + 0x14))));
        dVar13 = dVar10;
        if (dVar10 < (double)FLOAT_803e4ec0) {
          dVar13 = -dVar10;
        }
        if ((double)FLOAT_803e4ee8 < dVar13) {
          dVar13 = (double)FLOAT_803e4ee8;
        }
        *(short *)(iVar5 + 0x28) =
             (short)(int)(FLOAT_803e4eec * (float)((double)FLOAT_803e4ee8 - dVar13));
        if (*(char *)(iVar5 + 0x48) == '\x01') {
          (**(code **)(*DAT_803dca7c + 0x18))(param_1);
          *(undefined *)(iVar5 + 0x48) = 0;
        }
        if ((dVar10 < dVar12) && (-dVar12 < dVar10)) {
          fVar1 = FLOAT_803e4ef4;
          if ((float)(dVar11 + (double)(float)(dVar8 * (double)*(float *)(iVar3 + 0x80) +
                                              (double)(float)(dVar9 * (double)*(float *)(iVar3 + 
                                                  0x88)))) < FLOAT_803e4ec0) {
            fVar1 = FLOAT_803e4ef0;
          }
          dVar11 = (double)fVar1;
          iVar6 = FUN_80296ba0(iVar3);
          if (iVar6 == 0x1d7) {
            FUN_800200e8(0x468,1);
          }
          else {
            FUN_8000bb18(param_1,0x7a);
            iVar6 = 0;
            do {
              uVar4 = FUN_8002b9ec();
              (**(code **)(*DAT_803dca88 + 8))(uVar4,0x28b,0,4,0xffffffff,0);
              iVar6 = iVar6 + 1;
            } while (iVar6 < 4);
            *(float *)(iVar5 + 0x3c) = (float)(dVar8 * dVar11 + (double)*(float *)(iVar3 + 0xc));
            *(float *)(iVar5 + 0x44) = (float)(dVar9 * dVar11 + (double)*(float *)(iVar3 + 0x14));
            if ((*(char *)(iVar5 + 0x4a) == '\0') || (*(char *)(iVar5 + 0x4a) == '\x01')) {
              FUN_800378c4(iVar3,0x60003,iVar5 + 0x30,0);
            }
            *(undefined *)(iVar5 + 0x27) = 0x14;
          }
        }
      }
    }
  }
  if ((*(char *)(iVar5 + 0x24) == '\0') && (*(char *)(iVar5 + 0x48) == '\x01')) {
    (**(code **)(*DAT_803dca7c + 0x18))(param_1);
    *(undefined *)(iVar5 + 0x48) = 0;
  }
  fVar1 = FLOAT_803e4ec0;
  *(float *)(iVar5 + 4) = FLOAT_803e4ec0;
  *(float *)(iVar5 + 0xc) = fVar1;
  *(float *)(iVar5 + 0x14) = fVar1;
  *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar5 + 4);
  *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
  *(float *)(iVar5 + 0x18) = (float)((double)*(float *)(iVar5 + 0x14) + dVar14);
  *(undefined *)(iVar5 + 0x26) = 8;
  *(float *)(param_1 + 0x4c) = FLOAT_803e4ef8 * FLOAT_803db414 + *(float *)(param_1 + 0x4c);
  if (FLOAT_803e4ec8 < *(float *)(param_1 + 0x4c)) {
    *(float *)(param_1 + 0x4c) = *(float *)(param_1 + 0x4c) - FLOAT_803e4ec8;
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
  __psq_l0(auStack88,uVar7);
  __psq_l1(auStack88,uVar7);
  return;
}

