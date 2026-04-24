// Function: FUN_801f0b50
// Entry: 801f0b50
// Size: 2376 bytes

/* WARNING: Removing unreachable block (ram,0x801f1468) */
/* WARNING: Removing unreachable block (ram,0x801f1458) */
/* WARNING: Removing unreachable block (ram,0x801f1448) */
/* WARNING: Removing unreachable block (ram,0x801f1450) */
/* WARNING: Removing unreachable block (ram,0x801f1460) */
/* WARNING: Removing unreachable block (ram,0x801f1470) */

void FUN_801f0b50(short *param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  undefined4 uVar5;
  int iVar6;
  undefined2 uVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f26;
  double dVar14;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  undefined8 in_f31;
  double local_78;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
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
  iVar9 = *(int *)(param_1 + 0x26);
  iVar8 = *(int *)(param_1 + 0x5c);
  *(ushort *)(iVar8 + 0x2c) = *(short *)(iVar8 + 0x2c) - (ushort)DAT_803db410;
  iVar6 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
  if (iVar6 == 0) {
    if (*(short *)(iVar8 + 0x2c) < 0) {
      if (*(char *)(iVar8 + 0x25) == '\0') {
        cVar4 = *(char *)(iVar8 + 0x4e);
        if ((cVar4 == '\x03') || (cVar4 == '\x1e')) {
          *(undefined2 *)(iVar8 + 0x2c) = *(undefined2 *)(iVar8 + 0x30);
        }
        else {
          if ((cVar4 == '\0') && (*(short *)(iVar8 + 0x32) != -1)) {
            (**(code **)(*DAT_803dca7c + 0x20))(iVar8 + 0x32);
          }
          *(undefined2 *)(iVar8 + 0x2c) = *(undefined2 *)(iVar8 + 0x30);
        }
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5d10;
      }
      else {
        *(undefined2 *)(iVar8 + 0x2c) = 0x96;
      }
      *(undefined *)(iVar8 + 0x4d) = 0;
    }
    else if (*(short *)(iVar8 + 0x2c) < *(short *)(iVar8 + 0x2e)) {
      if (*(char *)(iVar8 + 0x4d) == '\0') {
        *(undefined *)(iVar8 + 0x4d) = 1;
        cVar4 = *(char *)(iVar8 + 0x4e);
        if (cVar4 == '\x01') {
          if (DAT_803ddc80 != (int *)0x0) {
            (**(code **)(*DAT_803ddc80 + 4))(param_1,2,0,0x10004,0xffffffff,0);
          }
        }
        else if ((cVar4 != '\x1e') && (cVar4 != '\0')) {
          (**(code **)(*DAT_803ddc80 + 4))(param_1,0,0,0x10004,0xffffffff,0);
        }
      }
      if (*(short *)(iVar8 + 0x2c) < 0x28) {
        if ((FLOAT_803e5d10 <= *(float *)(iVar8 + 0x1c)) && (*(char *)(iVar8 + 0x25) == '\0')) {
          *(float *)(iVar8 + 0x1c) = -(FLOAT_803e5d14 * FLOAT_803db414 - *(float *)(iVar8 + 0x1c));
        }
      }
      else if (*(short *)(iVar8 + 0x2c) < 0x8c) {
        if (*(char *)(iVar8 + 0x4d) == '\x01') {
          *(undefined *)(iVar8 + 0x4d) = 2;
          cVar4 = *(char *)(iVar8 + 0x4e);
          if (cVar4 == '\x01') {
            if (DAT_803ddc80 != (int *)0x0) {
              (**(code **)(*DAT_803ddc80 + 4))(param_1,3,0,0x10004,0xffffffff,0);
            }
          }
          else if (cVar4 == '\x1e') {
            if (DAT_803ddc80 != (int *)0x0) {
              uVar7 = (**(code **)(*DAT_803ddc80 + 4))(param_1,0x1e,0,0x10004,0xffffffff,0);
              *(undefined2 *)(iVar8 + 0x32) = uVar7;
            }
          }
          else if (cVar4 == '\0') {
            if ((DAT_803ddc80 != (int *)0x0) && (bVar1 = *(short *)(iVar8 + 0x32) == -1, bVar1)) {
              if (!bVar1) {
                (**(code **)(*DAT_803dca7c + 0x20))(iVar8 + 0x32);
              }
              if (DAT_803ddc80 != (int *)0x0) {
                uVar7 = (**(code **)(*DAT_803ddc80 + 4))(param_1,0,0,0x10004,0xffffffff,0);
                *(undefined2 *)(iVar8 + 0x32) = uVar7;
              }
            }
          }
          else if (DAT_803ddc80 != (int *)0x0) {
            (**(code **)(*DAT_803ddc80 + 4))(param_1,1,0,0x10004,0xffffffff,0);
          }
        }
      }
      else if (*(float *)(iVar8 + 0x1c) <= FLOAT_803e5d18) {
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5d1c * FLOAT_803db414 + *(float *)(iVar8 + 0x1c);
      }
    }
  }
  else if ((*(char *)(iVar8 + 0x4e) == '\0') && (*(short *)(iVar8 + 0x32) != -1)) {
    (**(code **)(*DAT_803dca7c + 0x20))(iVar8 + 0x32);
  }
  dVar17 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1a) ^ 0x80000000) -
                          DOUBLE_803e5d50);
  dVar16 = (double)(float)(dVar17 * dVar17);
  dVar11 = (double)FUN_80294204((double)((FLOAT_803e5d20 *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (int)*param_1 ^ 0x80000000) -
                                                DOUBLE_803e5d50)) / FLOAT_803e5d24));
  local_78 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  dVar12 = (double)FUN_80293e80((double)((FLOAT_803e5d20 * (float)(local_78 - DOUBLE_803e5d50)) /
                                        FLOAT_803e5d24));
  dVar14 = -(double)(float)((double)*(float *)(param_1 + 6) * dVar11 +
                           (double)(float)((double)*(float *)(param_1 + 10) * dVar12));
  iVar6 = FUN_8002b9ec();
  *(byte *)(iVar8 + 0x27) = *(char *)(iVar8 + 0x27) - DAT_803db410;
  if (*(char *)(iVar8 + 0x27) < '\x01') {
    *(undefined *)(iVar8 + 0x27) = 0;
  }
  else if ((*(char *)(iVar8 + 0x4e) == '\0') && (*(short *)(iVar8 + 0x32) != -1)) {
    (**(code **)(*DAT_803dca7c + 0x20))(iVar8 + 0x32);
  }
  if (((FLOAT_803e5d10 <
        (float)(dVar14 + (double)(float)(dVar11 * (double)*(float *)(iVar6 + 0xc) +
                                        (double)(float)(dVar12 * (double)*(float *)(iVar6 + 0x14))))
       ) && (*(char *)(iVar8 + 0x4e) != '\x02')) || (*(char *)(iVar8 + 0x4e) == '\x1e')) {
    *(ushort *)(iVar8 + 0x2a) = *(short *)(iVar8 + 0x2a) - (ushort)DAT_803db410;
    if (*(short *)(iVar8 + 0x2a) < 0) {
      *(undefined2 *)(iVar8 + 0x2a) = 0;
      *(undefined *)(iVar8 + 0x25) = 0;
    }
  }
  else {
    *(ushort *)(iVar8 + 0x2a) = *(short *)(iVar8 + 0x2a) + (ushort)DAT_803db410;
    if (0x3c < *(short *)(iVar8 + 0x2a)) {
      *(undefined2 *)(iVar8 + 0x2a) = 0x3c;
      *(undefined *)(iVar8 + 0x25) = 1;
    }
  }
  if (*(char *)(iVar8 + 0x25) == '\0') {
    *(byte *)(iVar8 + 0x24) = *(byte *)(iVar8 + 0x4d) & 3;
  }
  else {
    *(undefined *)(iVar8 + 0x24) = 2;
  }
  iVar9 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
  if (iVar9 != 0) {
    *(undefined *)(iVar8 + 0x24) = 0;
  }
  if (*(char *)(iVar8 + 0x27) == '\0') {
    *(undefined2 *)(iVar8 + 0x28) = 0;
  }
  if (((iVar6 != 0) && (*(char *)(iVar8 + 0x27) == '\0')) && (*(char *)(iVar8 + 0x24) == '\x02')) {
    local_78 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x26) ^ 0x80000000);
    dVar15 = (double)(FLOAT_803e5d28 + (float)(local_78 - DOUBLE_803e5d50));
    dVar13 = (double)(*(float *)(iVar6 + 0x10) - *(float *)(param_1 + 8));
    if ((dVar13 < dVar15) && (-(double)(float)((double)FLOAT_803e5d2c + dVar15) < dVar13)) {
      fVar2 = (float)((double)*(float *)(iVar6 + 0xc) - (double)*(float *)(param_1 + 6));
      fVar3 = (float)((double)*(float *)(iVar6 + 0x14) - (double)*(float *)(param_1 + 10));
      if ((double)(fVar2 * fVar2 + fVar3 * fVar3) < dVar16) {
        dVar13 = (double)(float)(dVar14 + (double)(float)(dVar11 * (double)*(float *)(iVar6 + 0xc) +
                                                         (double)(float)(dVar12 * (double)*(float *)
                                                  (iVar6 + 0x14))));
        dVar16 = dVar13;
        if (dVar13 < (double)FLOAT_803e5d10) {
          dVar16 = -dVar13;
        }
        if ((double)FLOAT_803e5d30 < dVar16) {
          dVar16 = (double)FLOAT_803e5d30;
        }
        *(short *)(iVar8 + 0x28) =
             (short)(int)(FLOAT_803e5d34 * (float)((double)FLOAT_803e5d30 - dVar16));
        if ((((double)FLOAT_803e5d38 <= dVar13) || (dVar13 <= (double)FLOAT_803e5d3c)) &&
           (*(char *)(iVar8 + 0x4c) == '\x01')) {
          (**(code **)(*DAT_803dca7c + 0x18))(param_1);
          *(undefined *)(iVar8 + 0x4c) = 0;
        }
        if ((dVar13 < dVar15) && (-dVar15 < dVar13)) {
          iVar9 = FUN_80296ba0(iVar6);
          if ((iVar9 == 0x1d7) && (*(char *)(iVar8 + 0x4e) != '\x01')) {
            FUN_800200e8(0x468,1);
          }
          else {
            fVar2 = FLOAT_803e5d44;
            if ((float)(dVar14 + (double)(float)(dVar11 * (double)*(float *)(iVar6 + 0x80) +
                                                (double)(float)(dVar12 * (double)*(float *)(iVar6 + 
                                                  0x88)))) < FLOAT_803e5d10) {
              fVar2 = FLOAT_803e5d40;
            }
            dVar14 = (double)fVar2;
            FUN_8000bae0((double)*(float *)(iVar6 + 0xc),(double)*(float *)(param_1 + 8),
                         (double)*(float *)(iVar6 + 0x14),param_1,0x1c9);
            if (*(short *)(*(int *)(iVar6 + 0xb8) + 0x81a) == 0) {
              uVar5 = 0x1f;
            }
            else {
              uVar5 = 0x23;
            }
            FUN_8000bb18(iVar6,uVar5);
            iVar9 = 0;
            do {
              uVar5 = FUN_8002b9ec();
              (**(code **)(*DAT_803dca88 + 8))(uVar5,0x198,0,4,0xffffffff,0);
              iVar9 = iVar9 + 1;
            } while (iVar9 < 4);
            *(float *)(iVar8 + 0x40) = (float)(dVar11 * dVar14 + (double)*(float *)(iVar6 + 0xc));
            *(float *)(iVar8 + 0x48) = (float)(dVar12 * dVar14 + (double)*(float *)(iVar6 + 0x14));
            cVar4 = *(char *)(iVar8 + 0x4e);
            if ((cVar4 == '\0') || (cVar4 == '\x01')) {
              FUN_800378c4(iVar6,0x60003,iVar8 + 0x34,0);
            }
            else if (((byte)(cVar4 - 2U) < 2) || (cVar4 == '\x1e')) {
              FUN_800378c4(iVar6,0x60004,iVar8 + 0x34,0);
            }
            *(undefined *)(iVar8 + 0x27) = 2;
          }
        }
      }
    }
  }
  if (*(char *)(iVar8 + 0x24) == '\0') {
    if ((*(char *)(iVar8 + 0x4e) == '\x1e') && (*(short *)(iVar8 + 0x32) != -1)) {
      (**(code **)(*DAT_803dca7c + 0x20))(iVar8 + 0x32);
    }
    if (*(char *)(iVar8 + 0x4c) == '\x01') {
      (**(code **)(*DAT_803dca7c + 0x18))(param_1);
      *(undefined *)(iVar8 + 0x4c) = 0;
    }
  }
  fVar2 = FLOAT_803e5d10;
  *(float *)(iVar8 + 4) = FLOAT_803e5d10;
  *(float *)(iVar8 + 0xc) = fVar2;
  *(float *)(iVar8 + 0x14) = fVar2;
  *(undefined4 *)(iVar8 + 8) = *(undefined4 *)(iVar8 + 4);
  *(undefined4 *)(iVar8 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
  *(float *)(iVar8 + 0x18) = (float)((double)*(float *)(iVar8 + 0x14) + dVar17);
  *(undefined *)(iVar8 + 0x26) = 8;
  *(float *)(param_1 + 0x4c) = FLOAT_803e5d48 * FLOAT_803db414 + *(float *)(param_1 + 0x4c);
  if (FLOAT_803e5d18 < *(float *)(param_1 + 0x4c)) {
    *(float *)(param_1 + 0x4c) = *(float *)(param_1 + 0x4c) - FLOAT_803e5d18;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  __psq_l0(auStack88,uVar10);
  __psq_l1(auStack88,uVar10);
  return;
}

