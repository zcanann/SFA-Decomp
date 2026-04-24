// Function: FUN_8023aa64
// Entry: 8023aa64
// Size: 17620 bytes

/* WARNING: Removing unreachable block (ram,0x8023ef14) */
/* WARNING: Removing unreachable block (ram,0x8023b088) */
/* WARNING: Removing unreachable block (ram,0x8023ef1c) */

void FUN_8023aa64(void)

{
  bool bVar1;
  float fVar2;
  short sVar3;
  short *psVar4;
  int iVar5;
  char cVar11;
  undefined2 uVar10;
  uint uVar6;
  int *piVar7;
  int iVar8;
  undefined4 uVar9;
  int iVar12;
  byte bVar13;
  int *piVar14;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  short local_130 [2];
  float local_12c;
  float local_128;
  float local_124;
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  int local_cc;
  int local_c8;
  int local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  double local_90;
  double local_88;
  double local_80;
  double local_78;
  longlong local_70;
  undefined4 local_68;
  uint uStack100;
  longlong local_60;
  longlong local_58;
  double local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  psVar4 = (short *)FUN_802860d0();
  piVar14 = *(int **)(psVar4 + 0x5c);
  iVar12 = 0;
  if (*(char *)((int)piVar14 + 0xb6) != '\0') {
    *(char *)((int)piVar14 + 0xb6) = *(char *)((int)piVar14 + 0xb6) + -1;
    goto LAB_8023ef14;
  }
  if (piVar14[1] == 0) {
    iVar5 = FUN_8002e0b4(0x47b78);
    piVar14[1] = iVar5;
  }
  if (piVar14[2] == 0) {
    iVar5 = FUN_8002e0b4(0x47b6a);
    piVar14[2] = iVar5;
  }
  if (piVar14[3] == 0) {
    iVar5 = FUN_8002e0b4(0x47dd9);
    piVar14[3] = iVar5;
  }
  if (*piVar14 == 0) {
    iVar5 = FUN_8022d768();
    *piVar14 = iVar5;
    if (*piVar14 == 0) goto LAB_8023ef14;
    piVar14[0x1c] = *(int *)(*piVar14 + 0x14);
    local_90 = (double)CONCAT44(0x43300000,DAT_803dc438 ^ 0x80000000);
    FUN_8022d460((double)(float)(local_90 - DOUBLE_803e7498),*piVar14);
  }
  for (bVar13 = 0; bVar13 < 4; bVar13 = bVar13 + 1) {
    uVar6 = (uint)bVar13;
    if (piVar14[uVar6 + 6] == 0) {
      iVar5 = FUN_8002e0b4((&DAT_8032c088)[uVar6]);
      piVar14[uVar6 + 6] = iVar5;
      if (piVar14[uVar6 + 6] != 0) {
        piVar14[uVar6 * 3 + 10] =
             (int)(*(float *)(piVar14[uVar6 + 6] + 0xc) - *(float *)(psVar4 + 6));
        piVar14[uVar6 * 3 + 0xb] =
             (int)(*(float *)(piVar14[uVar6 + 6] + 0x10) - *(float *)(psVar4 + 8));
        piVar14[uVar6 * 3 + 0xc] =
             (int)(*(float *)(piVar14[uVar6 + 6] + 0x14) - *(float *)(psVar4 + 10));
      }
    }
    else {
      *(float *)(piVar14[uVar6 + 6] + 0xc) = *(float *)(psVar4 + 6) + (float)piVar14[uVar6 * 3 + 10]
      ;
      *(float *)(piVar14[uVar6 + 6] + 0x10) =
           *(float *)(psVar4 + 8) + (float)piVar14[uVar6 * 3 + 0xb];
      *(float *)(piVar14[uVar6 + 6] + 0x14) =
           *(float *)(psVar4 + 10) + (float)piVar14[uVar6 * 3 + 0xc];
    }
  }
  bVar1 = piVar14[0x1f] != piVar14[0x20];
  piVar14[0x20] = piVar14[0x1f];
  fVar2 = FLOAT_803e74d4;
  piVar14[0x36] = (int)FLOAT_803e74d4;
  piVar14[0x37] = (int)fVar2;
  piVar14[0x38] = (int)fVar2;
  if ((-0x4000 < *(short *)(piVar14 + 0x28)) && (*psVar4 < 0x4000)) {
    iVar12 = 1;
  }
  FUN_8003842c(psVar4,iVar12,piVar14 + 0x30,piVar14 + 0x31,piVar14 + 0x32,0);
  fVar2 = FLOAT_803e74e0;
  if (iVar12 == 1) {
    piVar14[0x31] = (int)((float)piVar14[0x31] + FLOAT_803e74e0);
    piVar14[0x32] = (int)((float)piVar14[0x32] + fVar2);
  }
  iVar12 = piVar14[0x1f];
  if (iVar12 == 4) {
    if (piVar14[0x21] != 0) {
      switch(piVar14[0x22]) {
      default:
        piVar14[0x22] = 6;
        break;
      case 6:
        piVar14[0x22] = 7;
        break;
      case 7:
        piVar14[0x22] = 10;
        break;
      case 9:
        piVar14[0x22] = 8;
        break;
      case 10:
        piVar14[0x22] = 0x12;
        break;
      case 0xf:
        piVar14[0x22] = 9;
        break;
      case 0x11:
        piVar14[0x22] = 0x18;
        break;
      case 0x14:
        piVar14[0x22] = 0xb;
      }
      piVar14[0x21] = 0;
    }
  }
  else if (iVar12 < 4) {
    if (iVar12 == 2) {
      if ((bVar1) &&
         (*(byte *)((int)piVar14 + 0xad) = *(byte *)((int)piVar14 + 0xad) & 0xf9,
         piVar14[0x22] == 0x16)) {
        FUN_8023f39c(piVar14[1],1,1);
        FUN_8023f39c(piVar14[2],1,1);
      }
      if (piVar14[0x21] != 0) {
        switch(piVar14[0x22]) {
        default:
          piVar14[0x22] = 6;
          break;
        case 6:
          piVar14[0x22] = 7;
          break;
        case 7:
          piVar14[0x22] = 10;
          break;
        case 10:
          piVar14[0x22] = 0x12;
          break;
        case 0x11:
          piVar14[0x22] = 0x16;
          *(undefined2 *)(piVar14 + 0x28) = 0x8000;
          piVar14[0x1f] = piVar14[0x1f] + -1;
          break;
        case 0x14:
          piVar14[0x22] = 0xb;
        }
        piVar14[0x21] = 0;
      }
    }
    else if (iVar12 < 2) {
      if (0 < iVar12) {
        if (bVar1) {
          if (*(char *)(piVar14 + 0x2f) == '\0') {
            FUN_8023f39c(piVar14[1],2,1);
            FUN_8023f39c(piVar14[2],2,1);
          }
          else {
            *(undefined *)(piVar14 + 0x2f) = 0;
          }
          *(undefined *)((int)piVar14 + 0xae) = 10;
          *(undefined *)((int)piVar14 + 0xaf) = 10;
          *(undefined *)(piVar14 + 0x2c) = 10;
        }
        if (piVar14[0x21] != 0) {
          iVar12 = piVar14[0x22];
          if (iVar12 == 3) {
LAB_8023ad84:
            piVar14[0x22] = 0;
          }
          else if (iVar12 < 3) {
            if (iVar12 != 0) goto LAB_8023ad84;
            piVar14[0x22] = 1;
          }
          else {
            if (((iVar12 == 0x17) || (0x16 < iVar12)) || (iVar12 < 0x16)) goto LAB_8023ad84;
            if (*(char *)(piVar14 + 0x2e) == '\0') {
              piVar14[0x22] = 0;
            }
            else {
              piVar14[0x22] = 0x17;
            }
          }
          piVar14[0x21] = 0;
        }
      }
    }
    else {
      if (bVar1) {
        *(undefined *)((int)piVar14 + 0xae) = 0xf;
        *(undefined *)((int)piVar14 + 0xaf) = 0xf;
        *(undefined *)(piVar14 + 0x2c) = 0xf;
        piVar14[0x22] = 0;
        *(undefined *)((int)piVar14 + 0xb7) = 0;
      }
      if (piVar14[0x21] != 0) {
        iVar12 = piVar14[0x22];
        if (iVar12 == 3) {
          piVar14[0x22] = 4;
        }
        else if ((iVar12 < 3) || (4 < iVar12)) {
          piVar14[0x22] = 1;
        }
        else {
          *(char *)((int)piVar14 + 0xb7) = *(char *)((int)piVar14 + 0xb7) + '\x01';
          if (*(byte *)((int)piVar14 + 0xb7) < 4) {
            piVar14[0x22] = 0;
          }
          else {
            piVar14[0x1f] = piVar14[0x1f] + -1;
            piVar14[0x22] = 0x16;
            *(undefined2 *)(piVar14 + 0x28) = 0;
          }
        }
        piVar14[0x21] = 0;
      }
    }
  }
  else if (iVar12 == 6) {
    if (bVar1) {
      piVar14[0x22] = 0x1c;
      *(undefined *)(piVar14 + 0x2b) = 0;
    }
  }
  else if (iVar12 < 6) {
    if (bVar1) {
      piVar14[0x22] = 0xd;
      *(undefined *)(piVar14 + 0x2b) = 0;
    }
    if (piVar14[0x21] != 0) {
      switch(piVar14[0x22]) {
      default:
        *(undefined *)((int)piVar14 + 0xb1) = 3;
      case 0xf:
        piVar14[0x22] = 0x12;
        *(undefined *)(piVar14 + 0x2b) = 0;
        break;
      case 0x11:
        piVar14[0x22] = 0x18;
        break;
      case 0x14:
        if (*(char *)(piVar14 + 0x2b) == '\x01') {
          piVar14[0x22] = 0xb;
        }
        else if (*(char *)(piVar14 + 0x2b) == '\0') {
          piVar14[0x22] = 0x15;
        }
        *(byte *)(piVar14 + 0x2b) = *(byte *)(piVar14 + 0x2b) ^ 1;
        break;
      case 0x15:
        piVar14[0x22] = 0x12;
        break;
      case 0x19:
        piVar14[0x1f] = 6;
        break;
      case 0x1a:
        piVar14[0x22] = 0x1b;
      }
      piVar14[0x21] = 0;
    }
  }
  bVar1 = piVar14[0x22] != piVar14[0x23];
  piVar14[0x23] = piVar14[0x22];
  switch(piVar14[0x22]) {
  case 0:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c098;
      if (piVar14[0x1f] == 1) {
        piVar14[0x27] = (int)FLOAT_803e74e4;
      }
      else {
        piVar14[0x27] = (int)FLOAT_803e74e8;
      }
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      piVar14[0x21] = 1;
    }
    if ((uint)*(byte *)((int)piVar14 + 0xae) + (uint)*(byte *)((int)piVar14 + 0xaf) +
        (uint)*(byte *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      FUN_800200e8(0xd,0);
    }
    break;
  case 1:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0xc,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0c8;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x22] = 2;
      piVar14[0x21] = 0;
    }
    if ((uint)*(byte *)((int)piVar14 + 0xae) + (uint)*(byte *)((int)piVar14 + 0xaf) +
        (uint)*(byte *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      FUN_800200e8(0xd,0);
    }
    break;
  case 2:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0xe,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0d0;
      piVar14[0x27] = (int)FLOAT_803e74f0;
      *(undefined2 *)(piVar14 + 0x26) = 0xffff;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    FUN_8000da58(psVar4,0x467);
    *(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410;
    if (*(short *)(piVar14 + 0x26) < 0) {
      FUN_8023a268(psVar4,piVar14,0);
      *(short *)(piVar14 + 0x26) = (short)DAT_803dc43c;
    }
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      piVar14[0x22] = 3;
      piVar14[0x21] = 0;
    }
    if ((uint)*(byte *)((int)piVar14 + 0xae) + (uint)*(byte *)((int)piVar14 + 0xaf) +
        (uint)*(byte *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      FUN_800200e8(0xd,0);
    }
    break;
  case 3:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0xd,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0cc;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74cc < dVar16)) {
      dVar17 = (double)FLOAT_803e74cc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 4:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c098;
      FUN_800200e8(0xd,1);
      piVar14[0x27] = (int)FLOAT_803e7504;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74cc < dVar16)) {
      dVar17 = (double)FLOAT_803e74cc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      piVar14[0x21] = 1;
      FUN_800200e8(0xd,0);
    }
    if ((uint)*(byte *)((int)piVar14 + 0xae) + (uint)*(byte *)((int)piVar14 + 0xaf) +
        (uint)*(byte *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      FUN_800200e8(0xd,0);
    }
    break;
  case 5:
    iVar12 = *(int *)(piVar14[1] + 0xb8);
    iVar5 = *(int *)(piVar14[2] + 0xb8);
    if (bVar1) {
      FUN_8000bb18(psVar4,0x470);
      iVar8 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x16,0);
      *(undefined4 *)(iVar8 + 100) = DAT_8032c0f0;
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0x7f;
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xbf;
    }
    dVar19 = (double)*(float *)(psVar4 + 0x4c);
    if (DOUBLE_803e7540 <= dVar19) {
      dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 *
                                             (float)(DOUBLE_803e7548 *
                                                    (DOUBLE_803e7558 *
                                                     ((dVar19 - DOUBLE_803e7540) / DOUBLE_803e7560)
                                                    + DOUBLE_803e7550))) / FLOAT_803e74a4));
      local_50 = (double)CONCAT44(0x43300000,DAT_803dc48c ^ 0x80000000);
      piVar14[0x35] =
           (int)(float)((double)(float)(local_50 - DOUBLE_803e7498) * dVar19 +
                       (double)(float)piVar14[0x18]);
    }
    else {
      dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 *
                                             (float)(DOUBLE_803e7548 *
                                                    DOUBLE_803e7550 * (dVar19 / DOUBLE_803e7540))) /
                                            FLOAT_803e74a4));
      piVar14[0x35] = (int)(float)((double)FLOAT_803e74a8 * dVar19 + (double)(float)piVar14[0x18]);
    }
    if ((DOUBLE_803e7568 < (double)*(float *)(psVar4 + 0x4c)) &&
       ((*(byte *)(piVar14 + 0x3a) >> 6 & 1) == 0)) {
      iVar8 = FUN_800221a0(0,1);
      if (iVar8 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      FUN_8000bb18(psVar4,uVar9);
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xbf | 0x40;
    }
    if ((DOUBLE_803e7570 < (double)*(float *)(psVar4 + 0x4c)) && (-1 < *(char *)(piVar14 + 0x3a))) {
      FUN_8000bb18(psVar4,0x46d);
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0x7f | 0x80;
    }
    cVar11 = *(char *)(iVar12 + 0x23);
    if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
        (cVar11 = *(char *)(iVar5 + 0x23), cVar11 != '\x02')) && (cVar11 != '\x01')) {
      if ((double)*(float *)(psVar4 + 0x4c) < (double)FLOAT_803e74dc) {
        if (DOUBLE_803e7568 < (double)*(float *)(psVar4 + 0x4c)) {
          *(undefined2 *)(piVar14 + 0x28) = 0;
          uVar6 = countLeadingZeros(4 - piVar14[0x1f]);
          FUN_8023f39c(piVar14[1],1,(uVar6 >> 5) + 1 & 0xff);
          uVar6 = countLeadingZeros(4 - piVar14[0x1f]);
          FUN_8023f39c(piVar14[2],1,(uVar6 >> 5) + 1 & 0xff);
          *(byte *)((int)piVar14 + 0xad) = *(byte *)((int)piVar14 + 0xad) & 0xf9;
        }
      }
      else {
        piVar14[0x21] = 1;
      }
    }
    break;
  case 6:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c098;
      FUN_8023f39c(piVar14[2],4,0);
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e7508;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e750c < dVar17)) {
      dVar19 = (double)FLOAT_803e750c;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 7:
    if (bVar1) {
      FUN_8023f39c(piVar14[1],4,0);
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e7508;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e750c < dVar17)) {
      dVar19 = (double)FLOAT_803e750c;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 8:
    if (bVar1) {
      FUN_8023f39c(piVar14[2],6,0);
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74cc < dVar16)) {
      dVar17 = (double)FLOAT_803e74cc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 9:
    if (bVar1) {
      FUN_8023f39c(piVar14[1],6,0);
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74cc < dVar16)) {
      dVar17 = (double)FLOAT_803e74cc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 10:
    if ((*(byte *)((int)piVar14 + 0xad) & 6) == 6) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      if (piVar14[0x1f] < 5) {
        iVar12 = FUN_800221a0(0,1);
        if (iVar12 == 0) {
          uVar9 = 0x472;
        }
        else {
          uVar9 = 0x471;
        }
        FUN_8000bb18(psVar4,uVar9);
        piVar14[0x22] = 0x16;
        *(undefined2 *)(piVar14 + 0x28) = 0x8000;
      }
    }
    else {
      DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
      DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
      dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
      dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
      dVar19 = (double)FLOAT_803e7508;
      if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e750c < dVar17)) {
        dVar19 = (double)FLOAT_803e750c;
      }
      dVar17 = (double)FLOAT_803e74f4;
      if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
        dVar17 = (double)FLOAT_803e74f8;
      }
      local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
      dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498))
                                            / FLOAT_803e74a4));
      piVar14[0x33] =
           (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                       (double)(float)((double)(float)piVar14[0x16] + dVar19));
      local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
      dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498))
                                            / FLOAT_803e74a4));
      piVar14[0x34] =
           (int)(float)((double)FLOAT_803e74fc * dVar19 +
                       (double)(float)((double)(float)piVar14[0x17] + dVar17));
      piVar14[0x35] = piVar14[0x18];
      if (bVar1) {
        FUN_8023f39c(piVar14[1],5,0);
        FUN_8023f39c(piVar14[2],5,0);
      }
      bVar13 = *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad);
      if ((bVar13 & 1) != 0) {
        *(byte *)(*(int *)(psVar4 + 0x5c) + 0xad) = bVar13 & 0xfe;
        piVar14[0x21] = 1;
      }
    }
    break;
  case 0xb:
  case 0xd:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,1,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c09c;
      if (piVar14[0x1f] < 5) {
        FUN_8023f39c(piVar14[1],0,0);
        FUN_8023f39c(piVar14[2],0,0);
      }
      else {
        FUN_8023f39c(piVar14[1],9,1);
        FUN_8023f39c(piVar14[2],9,1);
        *(byte *)((int)piVar14 + 0xad) = *(byte *)((int)piVar14 + 0xad) | 6;
      }
    }
    if ((piVar14[0x1f] == 5) && (piVar14[0x22] == 0xb)) {
      for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
        iVar12 = FUN_8001ffb4(bVar13 + 0x108);
        if (iVar12 != 0) {
          *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023c584;
        }
      }
      *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = FUN_800221a0(0,5);
        FUN_800200e8(iVar12 + 0x108,1);
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023c584:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e7510;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74fc < dVar17)) {
      dVar19 = (double)FLOAT_803e74fc;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74fc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e7514 * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      iVar12 = piVar14[0x22];
      if (((iVar12 == 0xc) || (iVar12 < 0xc)) || (0xd < iVar12)) {
        piVar14[0x22] = 0xc;
      }
      else {
        piVar14[0x22] = 0xe;
      }
    }
    fVar2 = FLOAT_803e74b8 * *(float *)(psVar4 + 0x4c);
    if (FLOAT_803e74b8 <= fVar2) {
      dVar19 = (double)FLOAT_803e74cc;
    }
    else {
      dVar19 = -(double)(FLOAT_803e74c0 * FLOAT_803e74c4 * fVar2 - FLOAT_803e74bc);
      if (fVar2 < FLOAT_803e74c8) {
        FLOAT_803dddb8 = FLOAT_803dc4d4;
      }
    }
    FLOAT_803dddb8 = FLOAT_803dddb8 + FLOAT_803dc4d0;
    if (FLOAT_803e74d0 < FLOAT_803dddb8) {
      FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
    }
    FUN_80054fb0(dVar19,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
    break;
  case 0xc:
    fVar2 = FLOAT_803e74b8 * *(float *)(psVar4 + 0x4c) + FLOAT_803e74b8;
    if (FLOAT_803e74b8 <= fVar2) {
      dVar19 = (double)FLOAT_803e74cc;
    }
    else {
      dVar19 = -(double)(FLOAT_803e74c0 * FLOAT_803e74c4 * fVar2 - FLOAT_803e74bc);
      if (fVar2 < FLOAT_803e74c8) {
        FLOAT_803dddb8 = FLOAT_803dc4d4;
      }
    }
    FLOAT_803dddb8 = FLOAT_803dddb8 + FLOAT_803dc4d0;
    if (FLOAT_803e74d0 < FLOAT_803dddb8) {
      FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
    }
    FUN_80054fb0(dVar19,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,2,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0a0;
      if (piVar14[0x1f] < 5) {
        *(undefined *)((int)piVar14 + 0xb1) = 1;
      }
      *(short *)(piVar14 + 0x26) = (short)DAT_803dc460;
      piVar14[0x27] = (int)FLOAT_803e74d4;
    }
    FUN_8000da58(psVar4,0x466);
    if (piVar14[0x1f] == 5) {
      for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
        iVar12 = FUN_8001ffb4(bVar13 + 0x108);
        if (iVar12 != 0) {
          *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023cbdc;
        }
      }
      *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = FUN_800221a0(0,5);
        FUN_800200e8(iVar12 + 0x108,1);
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023cbdc:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74f4;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f8 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f8;
    }
    dVar17 = (double)FLOAT_803e7510;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74fc < dVar16)) {
      dVar17 = (double)FLOAT_803e74fc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74fc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e7514 * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    cVar11 = FUN_8023a6a4((double)FLOAT_803dc454,(double)FLOAT_803dc458,(double)FLOAT_803dc45c,
                          piVar14);
    if (cVar11 != '\0') {
      piVar14[0x22] = 0xf;
      FLOAT_803dddb8 = FLOAT_803dc4d4 + FLOAT_803dc4d0;
      if (FLOAT_803e74d0 < FLOAT_803dddb8) {
        FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
      }
      FUN_80054fb0((double)FLOAT_803e74bc,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
      FUN_80054fa4();
    }
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      FUN_80239fcc(psVar4,piVar14);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dc464 ^ 0x80000000);
      piVar14[0x27] = (int)((float)piVar14[0x27] + (float)(local_88 - DOUBLE_803e7498));
    }
    FUN_80239eac(psVar4,piVar14);
    if (*(char *)((int)piVar14 + 0xb5) == '\0') {
      if ((float)piVar14[0x32] < *(float *)(*piVar14 + 0x14)) {
        piVar14[0x22] = 0x10;
        *(undefined *)(piVar14 + 0x2e) = 1;
        *(int *)(*piVar14 + 0x14) = piVar14[0x32];
        piVar14[0x38] = (int)FLOAT_803e74d4;
        FLOAT_803dddb8 = FLOAT_803dc4d4 + FLOAT_803dc4d0;
        if (FLOAT_803e74d0 < FLOAT_803dddb8) {
          FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
        }
        FUN_80054fb0((double)FLOAT_803e74bc,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
        FUN_80054fa4();
        break;
      }
    }
    else {
      if (piVar14[0x1f] == 5) {
        piVar14[0x22] = 0x19;
      }
      else {
        piVar14[0x22] = 0xf;
      }
      FLOAT_803dddb8 = FLOAT_803dc4d4 + FLOAT_803dc4d0;
      if (FLOAT_803e74d0 < FLOAT_803dddb8) {
        FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
      }
      FUN_80054fb0((double)FLOAT_803e74bc,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
      FUN_80054fa4();
    }
    *(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410;
    if (*(short *)(piVar14 + 0x26) < 0) {
      piVar14[0x22] = 0xf;
      FLOAT_803dddb8 = FLOAT_803dc4d4 + FLOAT_803dc4d0;
      if (FLOAT_803e74d0 < FLOAT_803dddb8) {
        FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
      }
      FUN_80054fb0((double)FLOAT_803e74bc,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
      FUN_80054fa4();
    }
    break;
  case 0xe:
    fVar2 = FLOAT_803e74b8 * *(float *)(psVar4 + 0x4c) + FLOAT_803e74b8;
    if (FLOAT_803e74b8 <= fVar2) {
      dVar19 = (double)FLOAT_803e74cc;
    }
    else {
      dVar19 = -(double)(FLOAT_803e74c0 * FLOAT_803e74c4 * fVar2 - FLOAT_803e74bc);
      if (fVar2 < FLOAT_803e74c8) {
        FLOAT_803dddb8 = FLOAT_803dc4d4;
      }
    }
    FLOAT_803dddb8 = FLOAT_803dddb8 + FLOAT_803dc4d0;
    if (FLOAT_803e74d0 < FLOAT_803dddb8) {
      FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
    }
    FUN_80054fb0(dVar19,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,2,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0a0;
      *(undefined *)((int)piVar14 + 0xb1) = 0;
      FUN_800200e8(0x10,0);
      *(short *)(piVar14 + 0x26) = (short)DAT_803dc44c;
      piVar14[0x27] = (int)FLOAT_803e74d4;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7508;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e750c < dVar16)) {
      dVar17 = (double)FLOAT_803e750c;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74fc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e7514 * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    FUN_8023a6a4((double)FLOAT_803dc440,(double)FLOAT_803dc444,(double)FLOAT_803dc448,piVar14);
    FUN_8000da58(psVar4,0x466);
    if ((*(short *)(piVar14 + 0x26) != 0) &&
       (*(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410,
       *(short *)(piVar14 + 0x26) < 1)) {
      *(undefined2 *)(piVar14 + 0x26) = 0;
      FUN_800200e8(0xf,1);
    }
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      FUN_80239fcc(psVar4,piVar14);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dc450 ^ 0x80000000);
      piVar14[0x27] = (int)((float)piVar14[0x27] + (float)(local_88 - DOUBLE_803e7498));
    }
    FUN_80239eac(psVar4,piVar14);
    iVar12 = FUN_8001ffb4(0x10);
    if (iVar12 != 0) {
      FUN_800200e8(0x10,0);
      piVar14[0x22] = 0x1a;
      FLOAT_803dddb8 = FLOAT_803dc4d4 + FLOAT_803dc4d0;
      if (FLOAT_803e74d0 < FLOAT_803dddb8) {
        FLOAT_803dddb8 = FLOAT_803dddb8 - FLOAT_803e74d0;
      }
      FUN_80054fb0((double)FLOAT_803e74bc,(double)FLOAT_803dddb8,piVar14 + 0x30,&DAT_803dc4cc);
      FUN_80054fa4();
    }
    break;
  case 0xf:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x10,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0d8;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e7500;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74cc < dVar17)) {
      dVar19 = (double)FLOAT_803e74cc;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x10:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x10,0);
      *(float *)(iVar12 + 100) = FLOAT_803e7518;
    }
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar18 = (double)FLOAT_803e74d4;
    dVar19 = dVar18;
    if ((dVar18 <= dVar17) && (dVar19 = dVar17, dVar18 < dVar17)) {
      dVar19 = dVar18;
    }
    dVar18 = (double)FLOAT_803e74d4;
    dVar17 = dVar18;
    if ((dVar18 <= dVar16) && (dVar17 = dVar16, dVar18 < dVar16)) {
      dVar17 = dVar18;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74d4 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74d4 * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    iVar12 = *piVar14;
    local_e4 = ((float)piVar14[0x30] - *(float *)(iVar12 + 0xc)) * FLOAT_803dc468;
    local_e0 = ((float)piVar14[0x31] - *(float *)(iVar12 + 0x10)) * FLOAT_803dc468;
    local_dc = ((float)piVar14[0x32] - *(float *)(iVar12 + 0x14)) * FLOAT_803dc468;
    local_d8 = local_e4;
    local_d4 = local_e0;
    local_d0 = local_dc;
    FUN_8022d4ac(iVar12,&local_d8);
    fVar2 = -(FLOAT_803e74b0 * FLOAT_803db414 - (float)piVar14[0x2a]);
    if (fVar2 < FLOAT_803e74ec) {
      fVar2 = FLOAT_803e74ec;
    }
    piVar14[0x2a] = (int)fVar2;
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      *(ushort *)(*piVar14 + 6) = *(ushort *)(*piVar14 + 6) | 0x4000;
      piVar14[0x22] = 0x11;
    }
    break;
  case 0x11:
    if (bVar1) {
      FUN_8000bb18(psVar4,0x468);
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x15,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0ec;
      FUN_8022d64c(*piVar14,0xfffffffc);
    }
    fVar2 = -(FLOAT_803e74b0 * FLOAT_803db414 - (float)piVar14[0x2a]);
    if (fVar2 < FLOAT_803e74ec) {
      fVar2 = FLOAT_803e74ec;
    }
    piVar14[0x2a] = (int)fVar2;
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar18 = (double)FLOAT_803e74d4;
    dVar19 = dVar18;
    if ((dVar18 <= dVar17) && (dVar19 = dVar17, dVar18 < dVar17)) {
      dVar19 = dVar18;
    }
    dVar18 = (double)FLOAT_803e74d4;
    dVar17 = dVar18;
    if ((dVar18 <= dVar16) && (dVar17 = dVar16, dVar18 < dVar16)) {
      dVar17 = dVar18;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74d4 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74d4 * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x12:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x12,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0e0;
      FUN_8023f39c(piVar14[1],0,0);
      FUN_8023f39c(piVar14[2],0,0);
      if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) != '\0')) {
        FUN_800200e8(0xe,1);
      }
    }
    piVar14[0x1a] = (int)((float)piVar14[0x1a] - FLOAT_803e751c);
    fVar2 = (float)piVar14[0x1a];
    if (fVar2 < FLOAT_803e74d4) {
      fVar2 = FLOAT_803e74d4;
    }
    piVar14[0x1a] = (int)fVar2;
    dVar19 = (double)(float)piVar14[0x1a];
    piVar7 = (int *)FUN_8002b588(psVar4);
    iVar5 = *piVar7;
    dVar19 = (double)(longlong)(int)((double)FLOAT_803e74b4 * dVar19);
    for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(iVar5 + 0xf8); iVar12 = iVar12 + 1) {
      iVar8 = FUN_80028424(iVar5,iVar12);
      *(char *)(iVar8 + 0x43) = SUB81(dVar19,0);
      local_88 = dVar19;
    }
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
        iVar12 = FUN_8001ffb4(bVar13 + 0x108);
        if (iVar12 != 0) {
          *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d59c;
        }
      }
      *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = FUN_800221a0(0,5);
        FUN_800200e8(iVar12 + 0x108,1);
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d59c:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e74f4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74f8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74f8;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x22] = 0x13;
    }
    break;
  case 0x13:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x13,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0e4;
      if (piVar14[0x1f] == 5) {
        piVar14[0x27] = (int)FLOAT_803e74a8;
      }
      else {
        piVar14[0x27] = (int)FLOAT_803e74f0;
      }
      *(undefined2 *)(piVar14 + 0x26) = 0xffff;
    }
    FUN_8000da58(psVar4,0x469);
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
        iVar12 = FUN_8001ffb4(bVar13 + 0x108);
        if (iVar12 != 0) {
          *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d7cc;
        }
      }
      *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = FUN_800221a0(0,5);
        FUN_800200e8(iVar12 + 0x108,1);
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d7cc:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e7520;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74a8 < dVar17)) {
      dVar19 = (double)FLOAT_803e74a8;
    }
    dVar17 = (double)FLOAT_803e7524;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e7528 < dVar16)) {
      dVar17 = (double)FLOAT_803e7528;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74e8 * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    *(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410;
    iVar12 = (int)(float)piVar14[0x27];
    local_80 = (double)(longlong)iVar12;
    local_78 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
    piVar14[0x27] = (int)((float)piVar14[0x27] - (float)(local_78 - DOUBLE_803e7588));
    if (piVar14[0x1f] == 5) {
      local_130[0] = 300;
      local_130[1] = 600;
    }
    else {
      local_130[0] = 0x122;
      local_130[1] = 0x28;
    }
    for (bVar13 = 0; bVar13 < 2; bVar13 = bVar13 + 1) {
      if ((((piVar14[5] == 0) && (*(short *)(piVar14 + 0x26) <= local_130[bVar13])) &&
          (local_130[bVar13] < (short)iVar12)) && (cVar11 = FUN_8002e04c(), cVar11 != '\0')) {
        iVar5 = FUN_8002bdf4(0x24,0x819);
        *(int *)(iVar5 + 8) = piVar14[0x30];
        *(int *)(iVar5 + 0xc) = piVar14[0x31];
        *(int *)(iVar5 + 0x10) = piVar14[0x32];
        *(undefined *)(iVar5 + 4) = 1;
        *(undefined *)(iVar5 + 5) = 1;
        *(undefined2 *)(iVar5 + 0x20) = 0xffff;
        iVar5 = FUN_8002b5a0(psVar4);
        piVar14[5] = iVar5;
        if (piVar14[5] != 0) {
          *(undefined *)(piVar14[5] + 0x36) = 0xff;
          *(undefined *)(piVar14[5] + 0x37) = 0xff;
          piVar14[0x25] = DAT_803dc4ec;
        }
      }
    }
    if (*(short *)(piVar14 + 0x26) < 0) {
      FUN_8023a168(psVar4,piVar14);
      *(short *)(piVar14 + 0x26) = (short)DAT_803dc46c;
    }
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      piVar14[0x22] = 0x14;
    }
    break;
  case 0x14:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x14,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0e8;
    }
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
        iVar12 = FUN_8001ffb4(bVar13 + 0x108);
        if (iVar12 != 0) {
          *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023db24;
        }
      }
      *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = FUN_800221a0(0,5);
        FUN_800200e8(iVar12 + 0x108,1);
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023db24:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e752c;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74e8 < dVar16)) {
      dVar17 = (double)FLOAT_803e74e8;
    }
    local_78 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_78 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_80 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_80 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x15:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c098;
      FUN_800200e8(0xd,1);
      piVar14[0x27] = (int)FLOAT_803e7504;
    }
    for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
      iVar12 = FUN_8001ffb4(bVar13 + 0x108);
      if (iVar12 != 0) {
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023bb18;
      }
    }
    *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = FUN_800221a0(0,5);
      FUN_800200e8(iVar12 + 0x108,1);
      *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023bb18:
    DAT_803dddca = DAT_803dddca + DAT_803dc4bc;
    DAT_803dddc8 = DAT_803dddc8 + DAT_803dc4be;
    dVar17 = (double)(*(float *)(*piVar14 + 0xc) - (float)piVar14[0x16]);
    dVar16 = (double)(*(float *)(*piVar14 + 0x10) - (float)piVar14[0x17]);
    dVar19 = (double)FLOAT_803e74ec;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e74f0 < dVar17)) {
      dVar19 = (double)FLOAT_803e74f0;
    }
    dVar17 = (double)FLOAT_803e7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e74cc < dVar16)) {
      dVar17 = (double)FLOAT_803e74cc;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dddca ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_88 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x33] =
         (int)(float)((double)FLOAT_803e74cc * dVar16 +
                     (double)(float)((double)(float)piVar14[0x16] + dVar19));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dddc8 ^ 0x80000000);
    dVar19 = (double)FUN_80293e80((double)((FLOAT_803e74a0 * (float)(local_90 - DOUBLE_803e7498)) /
                                          FLOAT_803e74a4));
    piVar14[0x34] =
         (int)(float)((double)FLOAT_803e74fc * dVar19 +
                     (double)(float)((double)(float)piVar14[0x17] + dVar17));
    piVar14[0x35] = piVar14[0x18];
    piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803db414);
    if ((float)piVar14[0x27] < FLOAT_803e74d4) {
      piVar14[0x21] = 1;
      FUN_800200e8(0xd,0);
    }
    break;
  case 0x16:
    if (bVar1) {
      iVar12 = FUN_800221a0(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      FUN_8000bb18(psVar4,uVar9);
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c098;
    }
    if (*(char *)(piVar14 + 0x2e) != '\0') {
      iVar12 = *piVar14;
      local_fc = ((float)piVar14[0x30] - *(float *)(iVar12 + 0xc)) * FLOAT_803dc488;
      local_f8 = ((float)piVar14[0x31] - *(float *)(iVar12 + 0x10)) * FLOAT_803dc488;
      local_f4 = ((float)piVar14[0x32] - *(float *)(iVar12 + 0x14)) * FLOAT_803dc488;
      local_f0 = local_fc;
      local_ec = local_f8;
      local_e8 = local_f4;
      FUN_8022d4ac(iVar12,&local_f0);
      fVar2 = -(FLOAT_803e753c * FLOAT_803db414 - (float)piVar14[0x2a]);
      if (fVar2 < FLOAT_803e7538) {
        fVar2 = FLOAT_803e7538;
      }
      piVar14[0x2a] = (int)fVar2;
    }
    sVar3 = *(short *)(piVar14 + 0x28) - *psVar4;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar12 = (int)sVar3;
    if (iVar12 < 0) {
      iVar12 = -iVar12;
    }
    if (iVar12 < 2000) {
      cVar11 = *(char *)(*(int *)(piVar14[1] + 0xb8) + 0x23);
      if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
          (cVar11 = *(char *)(*(int *)(piVar14[2] + 0xb8) + 0x23), cVar11 != '\x02')) &&
         (cVar11 != '\x01')) {
        piVar14[0x21] = 1;
      }
    }
    break;
  case 0x17:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,3,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0a4;
      piVar14[0x39] = (int)FLOAT_803e74d4;
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xdf;
    }
    piVar14[0x39] = (int)((float)piVar14[0x39] + FLOAT_803db414);
    if ((FLOAT_803e7578 < (float)piVar14[0x39]) && ((*(byte *)(piVar14 + 0x3a) >> 5 & 1) == 0)) {
      FUN_8000bb18(psVar4,0x46f);
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xdf | 0x20;
    }
    if (FLOAT_803dc490 < *(float *)(psVar4 + 0x4c)) {
      dVar19 = (double)((float)piVar14[0x1c] - *(float *)(*piVar14 + 0x14));
      fVar2 = FLOAT_803e753c * FLOAT_803db414 + (float)piVar14[0x2a];
      if (FLOAT_803e74d4 < fVar2) {
        fVar2 = FLOAT_803e74d4;
      }
      piVar14[0x2a] = (int)fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(ushort *)(*piVar14 + 6) = *(ushort *)(*piVar14 + 6) & 0xbfff;
      sVar3 = FUN_8022d46c(*piVar14);
      local_50 = (double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000);
      iVar12 = (int)(dVar19 * (double)FLOAT_803dc49c + (double)(float)(local_50 - DOUBLE_803e7498));
      local_58 = (longlong)iVar12;
      FUN_8022d47c(*piVar14,iVar12);
      local_9c = FLOAT_803e74d4;
      local_98 = FLOAT_803e74d4;
      local_ac = (float)(dVar19 * (double)FLOAT_803dc498);
      local_b4 = FLOAT_803e74d4;
      local_b0 = FLOAT_803e74d4;
      local_94 = local_ac;
      FUN_8022d4ac(*piVar14,&local_b4);
    }
    else {
      piVar14[0x30] = *(int *)(psVar4 + 6);
      piVar14[0x31] = (int)(*(float *)(psVar4 + 8) - FLOAT_803e757c);
      piVar14[0x32] = (int)(*(float *)(psVar4 + 10) - FLOAT_803e7580);
      iVar12 = *piVar14;
      local_114 = ((float)piVar14[0x30] - *(float *)(iVar12 + 0xc)) * FLOAT_803dc494;
      local_110 = ((float)piVar14[0x31] - *(float *)(iVar12 + 0x10)) * FLOAT_803dc494;
      local_10c = ((float)piVar14[0x32] - *(float *)(iVar12 + 0x14)) * FLOAT_803dc494;
      local_108 = local_114;
      local_104 = local_110;
      local_100 = local_10c;
      FUN_8022d4ac(iVar12,&local_108);
    }
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x18:
    if (bVar1) {
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,0x11,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0dc;
      *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xdf;
    }
    if (FLOAT_803dc4a0 < *(float *)(psVar4 + 0x4c)) {
      dVar19 = (double)((float)piVar14[0x1c] - *(float *)(*piVar14 + 0x14));
      fVar2 = FLOAT_803e7514 * FLOAT_803db414 + (float)piVar14[0x2a];
      if (FLOAT_803e74d4 < fVar2) {
        fVar2 = FLOAT_803e74d4;
      }
      piVar14[0x2a] = (int)fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(ushort *)(*piVar14 + 6) = *(ushort *)(*piVar14 + 6) & 0xbfff;
      sVar3 = FUN_8022d46c(*piVar14);
      local_50 = (double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000);
      iVar12 = (int)(dVar19 * (double)FLOAT_803dc4ac + (double)(float)(local_50 - DOUBLE_803e7498));
      local_58 = (longlong)iVar12;
      FUN_8022d47c(*piVar14,iVar12);
      local_a8 = FLOAT_803e74d4;
      local_a4 = FLOAT_803e74d4;
      local_b8 = (float)(dVar19 * (double)FLOAT_803dc4a8);
      local_c0 = FLOAT_803e74d4;
      local_bc = FLOAT_803e74d4;
      local_a0 = local_b8;
      FUN_8022d4ac(*piVar14,&local_c0);
      if ((*(byte *)(piVar14 + 0x3a) >> 5 & 1) == 0) {
        FUN_8000bb18(psVar4,0x46f);
        *(byte *)(piVar14 + 0x3a) = *(byte *)(piVar14 + 0x3a) & 0xdf | 0x20;
      }
    }
    else {
      iVar12 = *piVar14;
      local_12c = ((float)piVar14[0x30] - *(float *)(iVar12 + 0xc)) * FLOAT_803dc4a4;
      local_128 = ((float)piVar14[0x31] - *(float *)(iVar12 + 0x10)) * FLOAT_803dc4a4;
      local_124 = ((float)piVar14[0x32] - *(float *)(iVar12 + 0x14)) * FLOAT_803dc4a4;
      local_120 = local_12c;
      local_11c = local_128;
      local_118 = local_124;
      FUN_8022d4ac(iVar12,&local_120);
    }
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x19:
  case 0x1a:
    if (bVar1) {
      FUN_8000bb18(psVar4,0x4a6);
      iVar12 = *(int *)(psVar4 + 0x5c);
      FUN_80030334((double)FLOAT_803e74d4,psVar4,4,0);
      *(undefined4 *)(iVar12 + 100) = DAT_8032c0a8;
    }
    if (FLOAT_803e74dc <= *(float *)(psVar4 + 0x4c)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x1b:
    if (bVar1) {
      FUN_800200e8(0x10,0);
      *(undefined2 *)(piVar14 + 0x26) = 0x1e;
      FUN_8022d308(*piVar14);
      *(int *)(*piVar14 + 0x14) = piVar14[0x1c];
      piVar14[0x2a] = (int)FLOAT_803e74d4;
    }
    piVar14[0x33] = piVar14[0x16];
    piVar14[0x34] = piVar14[0x17];
    piVar14[0x35] = piVar14[0x18];
    iVar12 = FUN_8001ffb4(0x10);
    if ((iVar12 != 0) &&
       (sVar3 = *(short *)(piVar14 + 0x26), *(short *)(piVar14 + 0x26) = sVar3 + -1, sVar3 == 0)) {
      FUN_800200e8(0x10,0);
      piVar14[0x21] = 1;
    }
    break;
  case 0x1c:
    if (bVar1) {
      FUN_8023fc8c(piVar14[3],1,0);
      FUN_80035f00(psVar4);
      *(undefined2 *)(piVar14 + 0x26) = 0x3c;
      piVar14[0x27] = (int)FLOAT_803e74d8;
      piVar14[0x33] = piVar14[0x16];
      piVar14[0x34] = piVar14[0x17];
      piVar14[0x35] = piVar14[0x18];
      fVar2 = FLOAT_803e74d4;
      *(float *)(psVar4 + 0x12) = FLOAT_803e74d4;
      *(float *)(psVar4 + 0x14) = fVar2;
      *(float *)(psVar4 + 0x16) = fVar2;
      piVar14[0x1d] = (int)FLOAT_803e74c8;
      piVar14[0x1e] = (int)FLOAT_803e7530;
    }
    piVar14[0x1a] = (int)((float)piVar14[0x1a] + FLOAT_803e751c);
    fVar2 = (float)piVar14[0x1a];
    if (FLOAT_803e7534 < fVar2) {
      fVar2 = FLOAT_803e7534;
    }
    piVar14[0x1a] = (int)fVar2;
    for (bVar13 = 0; bVar13 < 6; bVar13 = bVar13 + 1) {
      iVar12 = FUN_8001ffb4(bVar13 + 0x108);
      if (iVar12 != 0) {
        *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023de5c;
      }
    }
    *(ushort *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (ushort)DAT_803db410;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = FUN_800221a0(0,5);
      FUN_800200e8(iVar12 + 0x108,1);
      *(undefined2 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023de5c:
    *(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410;
    if (*(short *)(piVar14 + 0x26) < 0) {
      piVar14[0x27] = (int)((float)piVar14[0x27] - FLOAT_803e74dc);
      if (FLOAT_803e74d4 <= (float)piVar14[0x27]) {
        uVar10 = FUN_800221a0(0x14,0x1e);
        *(undefined2 *)(piVar14 + 0x26) = uVar10;
        local_78 = (double)(longlong)(int)-FLOAT_803dc470;
        local_80 = (double)(longlong)(int)FLOAT_803dc470;
        uVar6 = FUN_800221a0((int)-FLOAT_803dc470,(int)FLOAT_803dc470);
        local_88 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        piVar14[0x33] = (int)((float)piVar14[0x16] + (float)(local_88 - DOUBLE_803e7498));
        local_90 = (double)(longlong)(int)-FLOAT_803dc474;
        local_70 = (longlong)(int)FLOAT_803dc474;
        uStack100 = FUN_800221a0((int)-FLOAT_803dc474,(int)FLOAT_803dc474);
        uStack100 = uStack100 ^ 0x80000000;
        local_68 = 0x43300000;
        piVar14[0x34] =
             (int)((float)piVar14[0x17] +
                  (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e7498));
        local_60 = (longlong)(int)-FLOAT_803dc478;
        local_58 = (longlong)(int)FLOAT_803dc478;
        uVar6 = FUN_800221a0((int)-FLOAT_803dc478,(int)FLOAT_803dc478);
        local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        piVar14[0x35] = (int)((float)piVar14[0x18] + (float)(local_50 - DOUBLE_803e7498));
      }
      else {
        *(char *)(piVar14 + 0x2b) = *(char *)(piVar14 + 0x2b) + '\x01';
        if (*(byte *)(piVar14 + 0x2b) < 4) {
          piVar14[0x22] = 0x1d;
        }
        else {
          piVar14[0x1f] = 5;
          piVar14[0x20] = 5;
          *(undefined *)(piVar14 + 0x2b) = 0;
          piVar14[0x22] = 0x12;
          FUN_8023fc8c(piVar14[3],0,0);
          FUN_80035f20(psVar4);
        }
      }
    }
    if ((*(byte *)((int)piVar14 + 0xad) & 8) != 0) {
      FUN_8011f354(2);
      FUN_800200e8(1,1);
      FUN_800200e8(0x4b1,1);
      piVar14[0x22] = 0x1e;
      FUN_8004350c(0,0,1);
      uVar9 = FUN_800481b0(0xb);
      FUN_800437bc(uVar9,0x20000000);
      FUN_8000a518(0xf3,0);
    }
    dVar19 = (double)(float)piVar14[0x1a];
    piVar7 = (int *)FUN_8002b588(psVar4);
    iVar5 = *piVar7;
    dVar19 = (double)(longlong)(int)((double)FLOAT_803e74b4 * dVar19);
    for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(iVar5 + 0xf8); iVar12 = iVar12 + 1) {
      iVar8 = FUN_80028424(iVar5,iVar12);
      *(char *)(iVar8 + 0x43) = SUB81(dVar19,0);
      local_50 = dVar19;
    }
    break;
  case 0x1d:
    if (bVar1) {
      FUN_8023fc8c(piVar14[3],1,0);
      FUN_80035f00(psVar4);
      *(short *)(piVar14 + 0x26) = (short)DAT_803dc484;
      piVar14[0x33] = *(int *)(*piVar14 + 0xc);
      piVar14[0x34] = (int)(*(float *)(*piVar14 + 0x10) + FLOAT_803dc47c);
      piVar14[0x35] = (int)(*(float *)(*piVar14 + 0x14) + FLOAT_803dc480);
      fVar2 = FLOAT_803e74d4;
      *(float *)(psVar4 + 0x12) = FLOAT_803e74d4;
      *(float *)(psVar4 + 0x14) = fVar2;
      *(float *)(psVar4 + 0x16) = fVar2;
      iVar12 = FUN_800221a0(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      FUN_8000bb18(psVar4,uVar9);
    }
    *(ushort *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (ushort)DAT_803db410;
    if (*(short *)(piVar14 + 0x26) < 0) {
      piVar14[0x22] = 0x1c;
    }
    break;
  case 0x1e:
    iVar12 = FUN_8001ffb4(2);
    if (((iVar12 != 0) || (iVar12 = FUN_8001ffb4(3), iVar12 != 0)) ||
       (iVar12 = FUN_8001ffb4(4), iVar12 != 0)) {
      FUN_800200e8(0x405,0);
      (**(code **)(*DAT_803dcaac + 0x44))(0xb,7);
      FUN_8004350c(0,0,1);
      FUN_800481b0(0xb);
      FUN_80042f78();
      uVar9 = FUN_800481b0(0xb);
      FUN_80043560(uVar9,1);
      FUN_800552e8(0x4e,0);
      piVar14[0x1a] = (int)FLOAT_803e74d4;
      piVar14[0x22] = 0x1f;
    }
  }
  local_134 = FLOAT_803e7584 + (float)piVar14[0x2a];
  (**(code **)(*DAT_803dca50 + 0x60))(&local_134,4);
  *(float *)(psVar4 + 0x12) =
       (float)piVar14[0x1d] * ((float)piVar14[0x33] - *(float *)(psVar4 + 6)) +
       *(float *)(psVar4 + 0x12);
  *(float *)(psVar4 + 0x14) =
       (float)piVar14[0x1d] * ((float)piVar14[0x34] - *(float *)(psVar4 + 8)) +
       *(float *)(psVar4 + 0x14);
  *(float *)(psVar4 + 0x16) =
       (float)piVar14[0x1d] * ((float)piVar14[0x35] - *(float *)(psVar4 + 10)) +
       *(float *)(psVar4 + 0x16);
  *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * (float)piVar14[0x1e];
  *(float *)(psVar4 + 0x14) = *(float *)(psVar4 + 0x14) * (float)piVar14[0x1e];
  *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * (float)piVar14[0x1e];
  *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + *(float *)(psVar4 + 0x12);
  *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + *(float *)(psVar4 + 0x14);
  *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + *(float *)(psVar4 + 0x16);
  if (FLOAT_803e74d4 == (float)piVar14[0x38]) {
    if (*(char *)(piVar14 + 0x2e) == '\0') {
      piVar14[0x38] = (int)(FLOAT_803dc4b0 * ((float)piVar14[0x1c] - *(float *)(*piVar14 + 0x14)));
    }
    else {
      FUN_8023a6a4((double)FLOAT_803dc4b4,(double)FLOAT_803dc4b8,piVar14);
    }
  }
  if (*(int *)(*piVar14 + 0xc0) == 0) {
    local_cc = piVar14[0x36];
    local_c8 = piVar14[0x37];
    local_c4 = piVar14[0x38];
    FUN_8022d4cc(*piVar14,&local_cc);
  }
  sVar3 = *(short *)(piVar14 + 0x28) - *psVar4;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  *(short *)((int)piVar14 + 0xa2) =
       *(short *)((int)piVar14 + 0xa2) +
       (short)(((int)sVar3 / DAT_803dc430 - (int)*(short *)((int)piVar14 + 0xa2)) / DAT_803dc434);
  *(short *)(piVar14 + 0x29) =
       *(short *)(piVar14 + 0x29) +
       (short)((-(int)psVar4[1] / DAT_803dc430 - (int)*(short *)(piVar14 + 0x29)) / DAT_803dc434);
  *psVar4 = *psVar4 + *(short *)((int)piVar14 + 0xa2);
  psVar4[1] = psVar4[1] + *(short *)(piVar14 + 0x29);
  FUN_8002fa48((double)(float)piVar14[0x19],(double)FLOAT_803db414,psVar4,0);
  FUN_8023a3e4(psVar4,piVar14);
  FUN_8023a87c(psVar4,piVar14);
  iVar12 = piVar14[5];
  if (iVar12 != 0) {
    *(float *)(iVar12 + 0x14) = *(float *)(iVar12 + 0x14) - FLOAT_803e74d8;
    piVar14[0x25] = piVar14[0x25] - (uint)DAT_803db410;
    if (piVar14[0x25] < 0) {
      FUN_8002cbc4(piVar14[5]);
      piVar14[0x25] = 0;
      piVar14[5] = 0;
    }
  }
  if (piVar14[0x1f] < 6) {
    local_138 = FLOAT_803e7490;
    iVar12 = FUN_800380e0(psVar4,0x7e5,&local_138);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = FUN_80080340(*(undefined4 *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 8) = *(undefined4 *)(psVar4 + 6);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(undefined4 *)(psVar4 + 8);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(undefined4 *)(psVar4 + 10);
      }
    }
    local_13c = FLOAT_803e7490;
    iVar12 = FUN_800380e0(psVar4,0x1e,&local_13c);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = FUN_80080340(*(undefined4 *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 8) = *(undefined4 *)(psVar4 + 6);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(undefined4 *)(psVar4 + 8);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(undefined4 *)(psVar4 + 10);
      }
    }
    local_140 = FLOAT_803e7490;
    iVar12 = FUN_800380e0(psVar4,0x76f,&local_140);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = FUN_80080340(*(undefined4 *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 8) = *(undefined4 *)(psVar4 + 6);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(undefined4 *)(psVar4 + 8);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(undefined4 *)(psVar4 + 10);
      }
    }
    local_144 = FLOAT_803e7490;
    iVar12 = FUN_800380e0(psVar4,0x814,&local_144);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = FUN_80080340(*(undefined4 *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 8) = *(undefined4 *)(psVar4 + 6);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(undefined4 *)(psVar4 + 8);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(undefined4 *)(psVar4 + 10);
      }
    }
    local_148 = FLOAT_803e7490;
    iVar12 = FUN_800380e0(psVar4,0x6cf,&local_148);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = FUN_80080340(*(undefined4 *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 8) = *(undefined4 *)(psVar4 + 6);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(undefined4 *)(psVar4 + 8);
        *(undefined4 *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(undefined4 *)(psVar4 + 10);
      }
    }
  }
LAB_8023ef14:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_8028611c();
  return;
}

