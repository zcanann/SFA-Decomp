// Function: FUN_8023b15c
// Entry: 8023b15c
// Size: 17620 bytes

/* WARNING: Removing unreachable block (ram,0x8023f614) */
/* WARNING: Removing unreachable block (ram,0x8023f60c) */
/* WARNING: Removing unreachable block (ram,0x8023b174) */
/* WARNING: Removing unreachable block (ram,0x8023b16c) */
/* WARNING: Removing unreachable block (ram,0x8023b780) */

void FUN_8023b15c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  char cVar2;
  float fVar3;
  ushort uVar4;
  short sVar5;
  short *psVar6;
  int iVar7;
  undefined2 *puVar8;
  int *piVar9;
  int iVar10;
  uint uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  float *pfVar14;
  undefined4 uVar15;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar16;
  byte bVar17;
  int *piVar18;
  undefined8 uVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double in_f30;
  double dVar23;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
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
  float local_cc;
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
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  longlong local_70;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  longlong local_58;
  undefined8 local_50;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  psVar6 = (short *)FUN_80286834();
  piVar18 = *(int **)(psVar6 + 0x5c);
  iVar16 = 0;
  if (*(char *)((int)piVar18 + 0xb6) != '\0') {
    *(char *)((int)piVar18 + 0xb6) = *(char *)((int)piVar18 + 0xb6) + -1;
    goto LAB_8023f60c;
  }
  if (piVar18[1] == 0) {
    iVar7 = FUN_8002e1ac(0x47b78);
    piVar18[1] = iVar7;
  }
  if (piVar18[2] == 0) {
    iVar7 = FUN_8002e1ac(0x47b6a);
    piVar18[2] = iVar7;
  }
  if (piVar18[3] == 0) {
    iVar7 = FUN_8002e1ac(0x47dd9);
    piVar18[3] = iVar7;
  }
  if (*piVar18 == 0) {
    iVar7 = FUN_8022de2c();
    *piVar18 = iVar7;
    if (*piVar18 == 0) goto LAB_8023f60c;
    piVar18[0x1c] = *(int *)(*piVar18 + 0x14);
    local_90 = (double)CONCAT44(0x43300000,DAT_803dd0a0 ^ 0x80000000);
    FUN_8022db24((double)(float)(local_90 - DOUBLE_803e8130),*piVar18);
  }
  for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
    uVar11 = (uint)bVar17;
    if (piVar18[uVar11 + 6] == 0) {
      iVar7 = FUN_8002e1ac((&DAT_8032cce0)[uVar11]);
      piVar18[uVar11 + 6] = iVar7;
      if (piVar18[uVar11 + 6] != 0) {
        piVar18[uVar11 * 3 + 10] =
             (int)(*(float *)(piVar18[uVar11 + 6] + 0xc) - *(float *)(psVar6 + 6));
        piVar18[uVar11 * 3 + 0xb] =
             (int)(*(float *)(piVar18[uVar11 + 6] + 0x10) - *(float *)(psVar6 + 8));
        piVar18[uVar11 * 3 + 0xc] =
             (int)(*(float *)(piVar18[uVar11 + 6] + 0x14) - *(float *)(psVar6 + 10));
      }
    }
    else {
      *(float *)(piVar18[uVar11 + 6] + 0xc) =
           *(float *)(psVar6 + 6) + (float)piVar18[uVar11 * 3 + 10];
      *(float *)(piVar18[uVar11 + 6] + 0x10) =
           *(float *)(psVar6 + 8) + (float)piVar18[uVar11 * 3 + 0xb];
      *(float *)(piVar18[uVar11 + 6] + 0x14) =
           *(float *)(psVar6 + 10) + (float)piVar18[uVar11 * 3 + 0xc];
    }
  }
  bVar1 = piVar18[0x1f] != piVar18[0x20];
  piVar18[0x20] = piVar18[0x1f];
  fVar3 = FLOAT_803e816c;
  piVar18[0x36] = (int)FLOAT_803e816c;
  piVar18[0x37] = (int)fVar3;
  piVar18[0x38] = (int)fVar3;
  if ((-0x4000 < *(short *)(piVar18 + 0x28)) && (*psVar6 < 0x4000)) {
    iVar16 = 1;
  }
  piVar9 = piVar18 + 0x31;
  pfVar14 = (float *)(piVar18 + 0x32);
  uVar15 = 0;
  FUN_80038524(psVar6,iVar16,(float *)(piVar18 + 0x30),piVar9,pfVar14,0);
  fVar3 = FLOAT_803e8178;
  if (iVar16 == 1) {
    piVar18[0x31] = (int)((float)piVar18[0x31] + FLOAT_803e8178);
    piVar18[0x32] = (int)((float)piVar18[0x32] + fVar3);
  }
  iVar16 = piVar18[0x1f];
  if (iVar16 == 4) {
    if (piVar18[0x21] != 0) {
      switch(piVar18[0x22]) {
      default:
        piVar18[0x22] = 6;
        break;
      case 6:
        piVar18[0x22] = 7;
        break;
      case 7:
        piVar18[0x22] = 10;
        break;
      case 9:
        piVar18[0x22] = 8;
        break;
      case 10:
        piVar18[0x22] = 0x12;
        break;
      case 0xf:
        piVar18[0x22] = 9;
        break;
      case 0x11:
        piVar18[0x22] = 0x18;
        break;
      case 0x14:
        piVar18[0x22] = 0xb;
      }
      piVar18[0x21] = 0;
    }
  }
  else if (iVar16 < 4) {
    if (iVar16 == 2) {
      if ((bVar1) &&
         (*(byte *)((int)piVar18 + 0xad) = *(byte *)((int)piVar18 + 0xad) & 0xf9,
         piVar18[0x22] == 0x16)) {
        FUN_8023fa94(piVar18[1],'\x01','\x01');
        FUN_8023fa94(piVar18[2],'\x01','\x01');
      }
      if (piVar18[0x21] != 0) {
        switch(piVar18[0x22]) {
        default:
          piVar18[0x22] = 6;
          break;
        case 6:
          piVar18[0x22] = 7;
          break;
        case 7:
          piVar18[0x22] = 10;
          break;
        case 10:
          piVar18[0x22] = 0x12;
          break;
        case 0x11:
          piVar18[0x22] = 0x16;
          *(undefined2 *)(piVar18 + 0x28) = 0x8000;
          piVar18[0x1f] = piVar18[0x1f] + -1;
          break;
        case 0x14:
          piVar18[0x22] = 0xb;
        }
        piVar18[0x21] = 0;
      }
    }
    else if (iVar16 < 2) {
      if (0 < iVar16) {
        if (bVar1) {
          if (*(char *)(piVar18 + 0x2f) == '\0') {
            FUN_8023fa94(piVar18[1],'\x02','\x01');
            FUN_8023fa94(piVar18[2],'\x02','\x01');
          }
          else {
            *(undefined *)(piVar18 + 0x2f) = 0;
          }
          *(undefined *)((int)piVar18 + 0xae) = 10;
          *(undefined *)((int)piVar18 + 0xaf) = 10;
          *(undefined *)(piVar18 + 0x2c) = 10;
        }
        if (piVar18[0x21] != 0) {
          iVar16 = piVar18[0x22];
          if (iVar16 == 3) {
LAB_8023b47c:
            piVar18[0x22] = 0;
          }
          else if (iVar16 < 3) {
            if (iVar16 != 0) goto LAB_8023b47c;
            piVar18[0x22] = 1;
          }
          else {
            if (((iVar16 == 0x17) || (0x16 < iVar16)) || (iVar16 < 0x16)) goto LAB_8023b47c;
            if (*(char *)(piVar18 + 0x2e) == '\0') {
              piVar18[0x22] = 0;
            }
            else {
              piVar18[0x22] = 0x17;
            }
          }
          piVar18[0x21] = 0;
        }
      }
    }
    else {
      if (bVar1) {
        *(undefined *)((int)piVar18 + 0xae) = 0xf;
        *(undefined *)((int)piVar18 + 0xaf) = 0xf;
        *(undefined *)(piVar18 + 0x2c) = 0xf;
        piVar18[0x22] = 0;
        *(undefined *)((int)piVar18 + 0xb7) = 0;
      }
      if (piVar18[0x21] != 0) {
        iVar16 = piVar18[0x22];
        if (iVar16 == 3) {
          piVar18[0x22] = 4;
        }
        else if ((iVar16 < 3) || (4 < iVar16)) {
          piVar18[0x22] = 1;
        }
        else {
          *(char *)((int)piVar18 + 0xb7) = *(char *)((int)piVar18 + 0xb7) + '\x01';
          if (*(byte *)((int)piVar18 + 0xb7) < 4) {
            piVar18[0x22] = 0;
          }
          else {
            piVar18[0x1f] = piVar18[0x1f] + -1;
            piVar18[0x22] = 0x16;
            *(undefined2 *)(piVar18 + 0x28) = 0;
          }
        }
        piVar18[0x21] = 0;
      }
    }
  }
  else if (iVar16 == 6) {
    if (bVar1) {
      piVar18[0x22] = 0x1c;
      *(undefined *)(piVar18 + 0x2b) = 0;
    }
  }
  else if (iVar16 < 6) {
    if (bVar1) {
      piVar18[0x22] = 0xd;
      *(undefined *)(piVar18 + 0x2b) = 0;
    }
    if (piVar18[0x21] != 0) {
      switch(piVar18[0x22]) {
      default:
        *(undefined *)((int)piVar18 + 0xb1) = 3;
      case 0xf:
        piVar18[0x22] = 0x12;
        *(undefined *)(piVar18 + 0x2b) = 0;
        break;
      case 0x11:
        piVar18[0x22] = 0x18;
        break;
      case 0x14:
        if (*(char *)(piVar18 + 0x2b) == '\x01') {
          piVar18[0x22] = 0xb;
        }
        else if (*(char *)(piVar18 + 0x2b) == '\0') {
          piVar18[0x22] = 0x15;
        }
        *(byte *)(piVar18 + 0x2b) = *(byte *)(piVar18 + 0x2b) ^ 1;
        break;
      case 0x15:
        piVar18[0x22] = 0x12;
        break;
      case 0x19:
        piVar18[0x1f] = 6;
        break;
      case 0x1a:
        piVar18[0x22] = 0x1b;
      }
      piVar18[0x21] = 0;
    }
  }
  bVar1 = piVar18[0x22] != piVar18[0x23];
  piVar18[0x23] = piVar18[0x22];
  switch(piVar18[0x22]) {
  case 0:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf0;
      if (piVar18[0x1f] == 1) {
        piVar18[0x27] = (int)FLOAT_803e817c;
      }
      else {
        piVar18[0x27] = (int)FLOAT_803e8180;
      }
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((float)piVar18[0x27] < FLOAT_803e816c) {
      piVar18[0x21] = 1;
    }
    if ((uint)*(byte *)((int)piVar18 + 0xae) + (uint)*(byte *)((int)piVar18 + 0xaf) +
        (uint)*(byte *)(piVar18 + 0x2c) == 0) {
      piVar18[0x1f] = piVar18[0x1f] + 1;
      piVar18[0x22] = 5;
      piVar18[0x21] = 0;
      FUN_800201ac(0xd,0);
    }
    break;
  case 1:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0xc,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd20;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x22] = 2;
      piVar18[0x21] = 0;
    }
    if ((uint)*(byte *)((int)piVar18 + 0xae) + (uint)*(byte *)((int)piVar18 + 0xaf) +
        (uint)*(byte *)(piVar18 + 0x2c) == 0) {
      piVar18[0x1f] = piVar18[0x1f] + 1;
      piVar18[0x22] = 5;
      piVar18[0x21] = 0;
      FUN_800201ac(0xd,0);
    }
    break;
  case 2:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0xe,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd28;
      piVar18[0x27] = (int)FLOAT_803e8188;
      *(undefined2 *)(piVar18 + 0x26) = 0xffff;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    dVar21 = (double)FLOAT_803e8194;
    piVar18[0x34] =
         (int)(float)(dVar21 * dVar22 + (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    uVar19 = FUN_8000da78((uint)psVar6,0x467);
    *(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070;
    if (*(short *)(piVar18 + 0x26) < 0) {
      FUN_8023a960(uVar19,dVar21,param_3,param_4,param_5,param_6,param_7,param_8,psVar6,piVar18);
      *(short *)(piVar18 + 0x26) = (short)DAT_803dd0a4;
    }
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((float)piVar18[0x27] < FLOAT_803e816c) {
      piVar18[0x22] = 3;
      piVar18[0x21] = 0;
    }
    if ((uint)*(byte *)((int)piVar18 + 0xae) + (uint)*(byte *)((int)piVar18 + 0xaf) +
        (uint)*(byte *)(piVar18 + 0x2c) == 0) {
      piVar18[0x1f] = piVar18[0x1f] + 1;
      piVar18[0x22] = 5;
      piVar18[0x21] = 0;
      FUN_800201ac(0xd,0);
    }
    break;
  case 3:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0xd,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd24;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e8198;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8164 < dVar21)) {
      dVar20 = (double)FLOAT_803e8164;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 4:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf0;
      FUN_800201ac(0xd,1);
      piVar18[0x27] = (int)FLOAT_803e819c;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e8198;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8164 < dVar21)) {
      dVar20 = (double)FLOAT_803e8164;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((float)piVar18[0x27] < FLOAT_803e816c) {
      piVar18[0x21] = 1;
      FUN_800201ac(0xd,0);
    }
    if ((uint)*(byte *)((int)piVar18 + 0xae) + (uint)*(byte *)((int)piVar18 + 0xaf) +
        (uint)*(byte *)(piVar18 + 0x2c) == 0) {
      piVar18[0x1f] = piVar18[0x1f] + 1;
      piVar18[0x22] = 5;
      piVar18[0x21] = 0;
      FUN_800201ac(0xd,0);
    }
    break;
  case 5:
    iVar16 = *(int *)(piVar18[1] + 0xb8);
    iVar7 = *(int *)(piVar18[2] + 0xb8);
    if (bVar1) {
      FUN_8000bb38((uint)psVar6,0x470);
      iVar10 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x16,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar10 + 100) = DAT_8032cd48;
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0x7f;
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xbf;
    }
    param_5 = (double)*(float *)(psVar6 + 0x4c);
    if (DOUBLE_803e81d8 <= param_5) {
      param_4 = (double)FLOAT_803e8138;
      dVar22 = (double)FUN_802945e0();
      local_50 = (double)CONCAT44(0x43300000,DAT_803dd0f4 ^ 0x80000000);
      piVar18[0x35] =
           (int)(float)((double)(float)(local_50 - DOUBLE_803e8130) * dVar22 +
                       (double)(float)piVar18[0x18]);
    }
    else {
      dVar22 = (double)FUN_802945e0();
      piVar18[0x35] = (int)(float)((double)FLOAT_803e8140 * dVar22 + (double)(float)piVar18[0x18]);
    }
    if ((DOUBLE_803e8200 < (double)*(float *)(psVar6 + 0x4c)) &&
       ((*(byte *)(piVar18 + 0x3a) >> 6 & 1) == 0)) {
      uVar11 = FUN_80022264(0,1);
      if (uVar11 == 0) {
        uVar4 = 0x472;
      }
      else {
        uVar4 = 0x471;
      }
      FUN_8000bb38((uint)psVar6,uVar4);
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xbf | 0x40;
    }
    if ((DOUBLE_803e8208 < (double)*(float *)(psVar6 + 0x4c)) && (-1 < *(char *)(piVar18 + 0x3a))) {
      FUN_8000bb38((uint)psVar6,0x46d);
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0x7f | 0x80;
    }
    cVar2 = *(char *)(iVar16 + 0x23);
    if ((((cVar2 != '\x02') && (cVar2 != '\x01')) &&
        (cVar2 = *(char *)(iVar7 + 0x23), cVar2 != '\x02')) && (cVar2 != '\x01')) {
      if ((double)*(float *)(psVar6 + 0x4c) < (double)FLOAT_803e8174) {
        if (DOUBLE_803e8200 < (double)*(float *)(psVar6 + 0x4c)) {
          *(undefined2 *)(piVar18 + 0x28) = 0;
          uVar11 = countLeadingZeros(4 - piVar18[0x1f]);
          FUN_8023fa94(piVar18[1],'\x01',(char)(uVar11 >> 5) + '\x01');
          uVar11 = countLeadingZeros(4 - piVar18[0x1f]);
          FUN_8023fa94(piVar18[2],'\x01',(char)(uVar11 >> 5) + '\x01');
          *(byte *)((int)piVar18 + 0xad) = *(byte *)((int)piVar18 + 0xad) & 0xf9;
        }
      }
      else {
        piVar18[0x21] = 1;
      }
    }
    break;
  case 6:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf0;
      FUN_8023fa94(piVar18[2],'\x04','\0');
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e81a0;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e81a4 < dVar20)) {
      dVar22 = (double)FLOAT_803e81a4;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8180 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    bVar17 = *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad);
    if ((bVar17 & 1) != 0) {
      *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad) = bVar17 & 0xfe;
      piVar18[0x21] = 1;
    }
    break;
  case 7:
    if (bVar1) {
      FUN_8023fa94(piVar18[1],'\x04','\0');
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e81a0;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e81a4 < dVar20)) {
      dVar22 = (double)FLOAT_803e81a4;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8180 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    bVar17 = *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad);
    if ((bVar17 & 1) != 0) {
      *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad) = bVar17 & 0xfe;
      piVar18[0x21] = 1;
    }
    break;
  case 8:
    if (bVar1) {
      FUN_8023fa94(piVar18[2],'\x06','\0');
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e8198;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8164 < dVar21)) {
      dVar20 = (double)FLOAT_803e8164;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    bVar17 = *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad);
    if ((bVar17 & 1) != 0) {
      *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad) = bVar17 & 0xfe;
      piVar18[0x21] = 1;
    }
    break;
  case 9:
    if (bVar1) {
      FUN_8023fa94(piVar18[1],'\x06','\0');
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e8198;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8164 < dVar21)) {
      dVar20 = (double)FLOAT_803e8164;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    bVar17 = *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad);
    if ((bVar17 & 1) != 0) {
      *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad) = bVar17 & 0xfe;
      piVar18[0x21] = 1;
    }
    break;
  case 10:
    if ((*(byte *)((int)piVar18 + 0xad) & 6) == 6) {
      piVar18[0x1f] = piVar18[0x1f] + 1;
      if (piVar18[0x1f] < 5) {
        uVar11 = FUN_80022264(0,1);
        if (uVar11 == 0) {
          uVar4 = 0x472;
        }
        else {
          uVar4 = 0x471;
        }
        FUN_8000bb38((uint)psVar6,uVar4);
        piVar18[0x22] = 0x16;
        *(undefined2 *)(piVar18 + 0x28) = 0x8000;
      }
    }
    else {
      DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
      DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
      dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
      dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
      dVar22 = (double)FLOAT_803e81a0;
      if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e81a4 < dVar20)) {
        dVar22 = (double)FLOAT_803e81a4;
      }
      dVar20 = (double)FLOAT_803e818c;
      if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
        dVar20 = (double)FLOAT_803e8190;
      }
      local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
      dVar21 = (double)FUN_802945e0();
      piVar18[0x33] =
           (int)(float)((double)FLOAT_803e8180 * dVar21 +
                       (double)(float)((double)(float)piVar18[0x16] + dVar22));
      local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
      dVar22 = (double)FUN_802945e0();
      piVar18[0x34] =
           (int)(float)((double)FLOAT_803e8194 * dVar22 +
                       (double)(float)((double)(float)piVar18[0x17] + dVar20));
      piVar18[0x35] = piVar18[0x18];
      if (bVar1) {
        FUN_8023fa94(piVar18[1],'\x05','\0');
        FUN_8023fa94(piVar18[2],'\x05','\0');
      }
      bVar17 = *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad);
      if ((bVar17 & 1) != 0) {
        *(byte *)(*(int *)(psVar6 + 0x5c) + 0xad) = bVar17 & 0xfe;
        piVar18[0x21] = 1;
      }
    }
    break;
  case 0xb:
  case 0xd:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,1,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf4;
      if (piVar18[0x1f] < 5) {
        FUN_8023fa94(piVar18[1],'\0','\0');
        FUN_8023fa94(piVar18[2],'\0','\0');
      }
      else {
        FUN_8023fa94(piVar18[1],'\t','\x01');
        FUN_8023fa94(piVar18[2],'\t','\x01');
        *(byte *)((int)piVar18 + 0xad) = *(byte *)((int)piVar18 + 0xad) | 6;
      }
    }
    if ((piVar18[0x1f] == 5) && (piVar18[0x22] == 0xb)) {
      for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
        uVar11 = FUN_80020078(bVar17 + 0x108);
        if (uVar11 != 0) {
          *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
          goto LAB_8023cc7c;
        }
      }
      *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
      if (*(short *)((int)piVar18 + 0xa6) < 1) {
        uVar11 = FUN_80022264(0,5);
        FUN_800201ac(uVar11 + 0x108,1);
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
      }
    }
LAB_8023cc7c:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e81a8;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8194 < dVar20)) {
      dVar22 = (double)FLOAT_803e8194;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8194 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e81ac * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      iVar16 = piVar18[0x22];
      if (((iVar16 == 0xc) || (iVar16 < 0xc)) || (0xd < iVar16)) {
        piVar18[0x22] = 0xc;
      }
      else {
        piVar18[0x22] = 0xe;
      }
    }
    fVar3 = FLOAT_803e8150 * *(float *)(psVar6 + 0x4c);
    if (FLOAT_803e8150 <= fVar3) {
      dVar22 = (double)FLOAT_803e8164;
    }
    else {
      dVar22 = -(double)(FLOAT_803e8158 * FLOAT_803e815c * fVar3 - FLOAT_803e8154);
      if (fVar3 < FLOAT_803e8160) {
        FLOAT_803dea38 = FLOAT_803dd13c;
      }
    }
    FLOAT_803dea38 = FLOAT_803dea38 + FLOAT_803dd138;
    if (FLOAT_803e8168 < FLOAT_803dea38) {
      FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
    }
    FUN_8005512c(dVar22,(double)FLOAT_803dea38,piVar18 + 0x30,&DAT_803dd134);
    break;
  case 0xc:
    dVar22 = (double)FLOAT_803e8150;
    dVar21 = (double)(float)(dVar22 * (double)*(float *)(psVar6 + 0x4c) + dVar22);
    if (dVar22 <= dVar21) {
      dVar22 = (double)FLOAT_803e8164;
    }
    else {
      dVar22 = -(double)(FLOAT_803e8158 * (float)((double)FLOAT_803e815c * dVar21) - FLOAT_803e8154)
      ;
      if (dVar21 < (double)FLOAT_803e8160) {
        FLOAT_803dea38 = FLOAT_803dd13c;
      }
    }
    FLOAT_803dea38 = FLOAT_803dea38 + FLOAT_803dd138;
    if (FLOAT_803e8168 < FLOAT_803dea38) {
      FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
    }
    dVar20 = (double)FLOAT_803dea38;
    FUN_8005512c(dVar22,dVar20,piVar18 + 0x30,&DAT_803dd134);
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,dVar20,dVar21,param_4,param_5,param_6,param_7,param_8,
                   psVar6,2,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf8;
      if (piVar18[0x1f] < 5) {
        *(undefined *)((int)piVar18 + 0xb1) = 1;
      }
      *(short *)(piVar18 + 0x26) = (short)DAT_803dd0c8;
      piVar18[0x27] = (int)FLOAT_803e816c;
    }
    FUN_8000da78((uint)psVar6,0x466);
    if (piVar18[0x1f] == 5) {
      for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
        uVar11 = FUN_80020078(bVar17 + 0x108);
        if (uVar11 != 0) {
          *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
          goto LAB_8023d2d4;
        }
      }
      *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
      if (*(short *)((int)piVar18 + 0xa6) < 1) {
        uVar11 = FUN_80022264(0,5);
        FUN_800201ac(uVar11 + 0x108,1);
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
      }
    }
LAB_8023d2d4:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e818c;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8190 < dVar20)) {
      dVar22 = (double)FLOAT_803e8190;
    }
    dVar20 = (double)FLOAT_803e81a8;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8194 < dVar21)) {
      dVar20 = (double)FLOAT_803e8194;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8194 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e81ac * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    dVar22 = (double)FLOAT_803dd0c0;
    dVar21 = (double)FLOAT_803dd0c4;
    uVar15 = FUN_8023ad9c((double)FLOAT_803dd0bc,dVar22,dVar21,piVar18);
    if ((char)uVar15 != '\0') {
      piVar18[0x22] = 0xf;
      FLOAT_803dea38 = FLOAT_803dd13c + FLOAT_803dd138;
      if (FLOAT_803e8168 < FLOAT_803dea38) {
        FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
      }
      dVar22 = (double)FLOAT_803dea38;
      FUN_8005512c((double)FLOAT_803e8154,dVar22,piVar18 + 0x30,&DAT_803dd134);
      FUN_80055120();
    }
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((double)(float)piVar18[0x27] < (double)FLOAT_803e816c) {
      FUN_8023a6c4((double)(float)piVar18[0x27],dVar22,dVar21,param_4,param_5,param_6,param_7,
                   param_8);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dd0cc ^ 0x80000000);
      piVar18[0x27] = (int)((float)piVar18[0x27] + (float)(local_88 - DOUBLE_803e8130));
    }
    FUN_8023a5a4();
    if (*(char *)((int)piVar18 + 0xb5) == '\0') {
      if ((float)piVar18[0x32] < *(float *)(*piVar18 + 0x14)) {
        piVar18[0x22] = 0x10;
        *(undefined *)(piVar18 + 0x2e) = 1;
        *(int *)(*piVar18 + 0x14) = piVar18[0x32];
        piVar18[0x38] = (int)FLOAT_803e816c;
        FLOAT_803dea38 = FLOAT_803dd13c + FLOAT_803dd138;
        if (FLOAT_803e8168 < FLOAT_803dea38) {
          FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
        }
        FUN_8005512c((double)FLOAT_803e8154,(double)FLOAT_803dea38,piVar18 + 0x30,&DAT_803dd134);
        FUN_80055120();
        break;
      }
    }
    else {
      if (piVar18[0x1f] == 5) {
        piVar18[0x22] = 0x19;
      }
      else {
        piVar18[0x22] = 0xf;
      }
      FLOAT_803dea38 = FLOAT_803dd13c + FLOAT_803dd138;
      if (FLOAT_803e8168 < FLOAT_803dea38) {
        FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
      }
      FUN_8005512c((double)FLOAT_803e8154,(double)FLOAT_803dea38,piVar18 + 0x30,&DAT_803dd134);
      FUN_80055120();
    }
    *(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070;
    if (*(short *)(piVar18 + 0x26) < 0) {
      piVar18[0x22] = 0xf;
      FLOAT_803dea38 = FLOAT_803dd13c + FLOAT_803dd138;
      if (FLOAT_803e8168 < FLOAT_803dea38) {
        FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
      }
      FUN_8005512c((double)FLOAT_803e8154,(double)FLOAT_803dea38,piVar18 + 0x30,&DAT_803dd134);
      FUN_80055120();
    }
    break;
  case 0xe:
    dVar22 = (double)FLOAT_803e8150;
    dVar21 = (double)(float)(dVar22 * (double)*(float *)(psVar6 + 0x4c) + dVar22);
    if (dVar22 <= dVar21) {
      dVar22 = (double)FLOAT_803e8164;
    }
    else {
      dVar22 = -(double)(FLOAT_803e8158 * (float)((double)FLOAT_803e815c * dVar21) - FLOAT_803e8154)
      ;
      if (dVar21 < (double)FLOAT_803e8160) {
        FLOAT_803dea38 = FLOAT_803dd13c;
      }
    }
    FLOAT_803dea38 = FLOAT_803dea38 + FLOAT_803dd138;
    if (FLOAT_803e8168 < FLOAT_803dea38) {
      FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
    }
    dVar20 = (double)FLOAT_803dea38;
    FUN_8005512c(dVar22,dVar20,piVar18 + 0x30,&DAT_803dd134);
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,dVar20,dVar21,param_4,param_5,param_6,param_7,param_8,
                   psVar6,2,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf8;
      *(undefined *)((int)piVar18 + 0xb1) = 0;
      FUN_800201ac(0x10,0);
      *(short *)(piVar18 + 0x26) = (short)DAT_803dd0b4;
      piVar18[0x27] = (int)FLOAT_803e816c;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e81a0;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e81a4 < dVar21)) {
      dVar20 = (double)FLOAT_803e81a4;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8194 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e81ac * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    dVar22 = (double)FLOAT_803dd0ac;
    dVar21 = (double)FLOAT_803dd0b0;
    FUN_8023ad9c((double)FLOAT_803dd0a8,dVar22,dVar21,piVar18);
    FUN_8000da78((uint)psVar6,0x466);
    if ((*(short *)(piVar18 + 0x26) != 0) &&
       (*(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070,
       *(short *)(piVar18 + 0x26) < 1)) {
      *(undefined2 *)(piVar18 + 0x26) = 0;
      FUN_800201ac(0xf,1);
    }
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((double)(float)piVar18[0x27] < (double)FLOAT_803e816c) {
      FUN_8023a6c4((double)(float)piVar18[0x27],dVar22,dVar21,param_4,param_5,param_6,param_7,
                   param_8);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dd0b8 ^ 0x80000000);
      piVar18[0x27] = (int)((float)piVar18[0x27] + (float)(local_88 - DOUBLE_803e8130));
    }
    FUN_8023a5a4();
    uVar11 = FUN_80020078(0x10);
    if (uVar11 != 0) {
      FUN_800201ac(0x10,0);
      piVar18[0x22] = 0x1a;
      FLOAT_803dea38 = FLOAT_803dd13c + FLOAT_803dd138;
      if (FLOAT_803e8168 < FLOAT_803dea38) {
        FLOAT_803dea38 = FLOAT_803dea38 - FLOAT_803e8168;
      }
      FUN_8005512c((double)FLOAT_803e8154,(double)FLOAT_803dea38,piVar18 + 0x30,&DAT_803dd134);
      FUN_80055120();
    }
    break;
  case 0xf:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x10,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd30;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8198;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8164 < dVar20)) {
      dVar22 = (double)FLOAT_803e8164;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8180 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x10:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x10,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(float *)(iVar16 + 100) = FLOAT_803e81b0;
    }
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar23 = (double)FLOAT_803e816c;
    dVar22 = dVar23;
    if ((dVar23 <= dVar20) && (dVar22 = dVar20, dVar23 < dVar20)) {
      dVar22 = dVar23;
    }
    dVar23 = (double)FLOAT_803e816c;
    dVar20 = dVar23;
    if ((dVar23 <= dVar21) && (dVar20 = dVar21, dVar23 < dVar21)) {
      dVar20 = dVar23;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e816c * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e816c * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    iVar16 = *piVar18;
    local_e4 = ((float)piVar18[0x30] - *(float *)(iVar16 + 0xc)) * FLOAT_803dd0d0;
    local_e0 = ((float)piVar18[0x31] - *(float *)(iVar16 + 0x10)) * FLOAT_803dd0d0;
    local_dc = ((float)piVar18[0x32] - *(float *)(iVar16 + 0x14)) * FLOAT_803dd0d0;
    local_d8 = local_e4;
    local_d4 = local_e0;
    local_d0 = local_dc;
    FUN_8022db70(iVar16,&local_d8);
    fVar3 = -(FLOAT_803e8148 * FLOAT_803dc074 - (float)piVar18[0x2a]);
    if (fVar3 < FLOAT_803e8184) {
      fVar3 = FLOAT_803e8184;
    }
    piVar18[0x2a] = (int)fVar3;
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      *(ushort *)(*piVar18 + 6) = *(ushort *)(*piVar18 + 6) | 0x4000;
      piVar18[0x22] = 0x11;
    }
    break;
  case 0x11:
    if (bVar1) {
      FUN_8000bb38((uint)psVar6,0x468);
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x15,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd44;
      FUN_8022dd10(*piVar18,-4);
    }
    fVar3 = -(FLOAT_803e8148 * FLOAT_803dc074 - (float)piVar18[0x2a]);
    if (fVar3 < FLOAT_803e8184) {
      fVar3 = FLOAT_803e8184;
    }
    piVar18[0x2a] = (int)fVar3;
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar23 = (double)FLOAT_803e816c;
    dVar22 = dVar23;
    if ((dVar23 <= dVar20) && (dVar22 = dVar20, dVar23 < dVar20)) {
      dVar22 = dVar23;
    }
    dVar23 = (double)FLOAT_803e816c;
    dVar20 = dVar23;
    if ((dVar23 <= dVar21) && (dVar20 = dVar21, dVar23 < dVar21)) {
      dVar20 = dVar23;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e816c * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e816c * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x12:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x12,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd38;
      FUN_8023fa94(piVar18[1],'\0','\0');
      FUN_8023fa94(piVar18[2],'\0','\0');
      if ((piVar18[0x1f] == 5) && (*(char *)(piVar18 + 0x2b) != '\0')) {
        FUN_800201ac(0xe,1);
      }
    }
    piVar18[0x1a] = (int)((float)piVar18[0x1a] - FLOAT_803e81b4);
    fVar3 = (float)piVar18[0x1a];
    if (fVar3 < FLOAT_803e816c) {
      fVar3 = FLOAT_803e816c;
    }
    piVar18[0x1a] = (int)fVar3;
    dVar22 = (double)(float)piVar18[0x1a];
    piVar9 = (int *)FUN_8002b660((int)psVar6);
    iVar7 = *piVar9;
    dVar22 = (double)(longlong)(int)((double)FLOAT_803e814c * dVar22);
    for (iVar16 = 0; iVar16 < (int)(uint)*(byte *)(iVar7 + 0xf8); iVar16 = iVar16 + 1) {
      iVar10 = FUN_800284e8(iVar7,iVar16);
      *(char *)(iVar10 + 0x43) = SUB81(dVar22,0);
      local_88 = dVar22;
    }
    if ((piVar18[0x1f] == 5) && (*(char *)(piVar18 + 0x2b) == '\0')) {
      for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
        uVar11 = FUN_80020078(bVar17 + 0x108);
        if (uVar11 != 0) {
          *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
          goto LAB_8023dc94;
        }
      }
      *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
      if (*(short *)((int)piVar18 + 0xa6) < 1) {
        uVar11 = FUN_80022264(0,5);
        FUN_800201ac(uVar11 + 0x108,1);
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
      }
    }
LAB_8023dc94:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e818c;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8190 < dVar21)) {
      dVar20 = (double)FLOAT_803e8190;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8180 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x22] = 0x13;
    }
    break;
  case 0x13:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x13,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd3c;
      if (piVar18[0x1f] == 5) {
        piVar18[0x27] = (int)FLOAT_803e8140;
      }
      else {
        piVar18[0x27] = (int)FLOAT_803e8188;
      }
      *(undefined2 *)(piVar18 + 0x26) = 0xffff;
    }
    FUN_8000da78((uint)psVar6,0x469);
    if ((piVar18[0x1f] == 5) && (*(char *)(piVar18 + 0x2b) == '\0')) {
      for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
        uVar11 = FUN_80020078(bVar17 + 0x108);
        if (uVar11 != 0) {
          *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
          goto LAB_8023dec4;
        }
      }
      *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
      if (*(short *)((int)piVar18 + 0xa6) < 1) {
        uVar11 = FUN_80022264(0,5);
        FUN_800201ac(uVar11 + 0x108,1);
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
      }
    }
LAB_8023dec4:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e81b8;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8140 < dVar20)) {
      dVar22 = (double)FLOAT_803e8140;
    }
    dVar20 = (double)FLOAT_803e81bc;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e81c0 < dVar21)) {
      dVar20 = (double)FLOAT_803e81c0;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8180 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    *(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070;
    dVar22 = DOUBLE_803e8220;
    dVar21 = (double)(float)piVar18[0x27];
    iVar16 = (int)(float)piVar18[0x27];
    local_80 = (longlong)iVar16;
    local_78 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    piVar18[0x27] = (int)(float)(dVar21 - (double)(float)(local_78 - DOUBLE_803e8220));
    if (piVar18[0x1f] == 5) {
      local_130[0] = 300;
      local_130[1] = 600;
    }
    else {
      local_130[0] = 0x122;
      local_130[1] = 0x28;
    }
    for (bVar17 = 0; bVar17 < 2; bVar17 = bVar17 + 1) {
      if ((((piVar18[5] == 0) && (*(short *)(piVar18 + 0x26) <= local_130[bVar17])) &&
          (local_130[bVar17] < (short)iVar16)) && (uVar11 = FUN_8002e144(), (uVar11 & 0xff) != 0)) {
        puVar8 = FUN_8002becc(0x24,0x819);
        *(int *)(puVar8 + 4) = piVar18[0x30];
        *(int *)(puVar8 + 6) = piVar18[0x31];
        *(int *)(puVar8 + 8) = piVar18[0x32];
        *(undefined *)(puVar8 + 2) = 1;
        *(undefined *)((int)puVar8 + 5) = 1;
        puVar8[0x10] = 0xffff;
        iVar7 = FUN_8002b678(dVar22,dVar21,param_3,param_4,param_5,param_6,param_7,param_8,
                             (int)psVar6,puVar8);
        piVar18[5] = iVar7;
        if (piVar18[5] != 0) {
          *(undefined *)(piVar18[5] + 0x36) = 0xff;
          *(undefined *)(piVar18[5] + 0x37) = 0xff;
          piVar18[0x25] = DAT_803dd154;
        }
      }
    }
    if (*(short *)(piVar18 + 0x26) < 0) {
      FUN_8023a860(dVar22,dVar21,param_3,param_4,param_5,param_6,param_7,param_8,psVar6,(int)piVar18
                  );
      *(short *)(piVar18 + 0x26) = (short)DAT_803dd0d4;
    }
    if ((float)piVar18[0x27] < FLOAT_803e816c) {
      piVar18[0x22] = 0x14;
    }
    break;
  case 0x14:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x14,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd40;
    }
    if ((piVar18[0x1f] == 5) && (*(char *)(piVar18 + 0x2b) == '\0')) {
      for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
        uVar11 = FUN_80020078(bVar17 + 0x108);
        if (uVar11 != 0) {
          *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
          goto LAB_8023e21c;
        }
      }
      *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
      if (*(short *)((int)piVar18 + 0xa6) < 1) {
        uVar11 = FUN_80022264(0,5);
        FUN_800201ac(uVar11 + 0x108,1);
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
      }
    }
LAB_8023e21c:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e81c4;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8180 < dVar21)) {
      dVar20 = (double)FLOAT_803e8180;
    }
    local_78 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_80 = CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x15:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf0;
      FUN_800201ac(0xd,1);
      piVar18[0x27] = (int)FLOAT_803e819c;
    }
    for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
      uVar11 = FUN_80020078(bVar17 + 0x108);
      if (uVar11 != 0) {
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
        goto LAB_8023c210;
      }
    }
    *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
    if (*(short *)((int)piVar18 + 0xa6) < 1) {
      uVar11 = FUN_80022264(0,5);
      FUN_800201ac(uVar11 + 0x108,1);
      *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
    }
LAB_8023c210:
    DAT_803dea4a = DAT_803dea4a + DAT_803dd124;
    DAT_803dea48 = DAT_803dea48 + DAT_803dd126;
    dVar20 = (double)(*(float *)(*piVar18 + 0xc) - (float)piVar18[0x16]);
    dVar21 = (double)(*(float *)(*piVar18 + 0x10) - (float)piVar18[0x17]);
    dVar22 = (double)FLOAT_803e8184;
    if ((dVar22 <= dVar20) && (dVar22 = dVar20, (double)FLOAT_803e8188 < dVar20)) {
      dVar22 = (double)FLOAT_803e8188;
    }
    dVar20 = (double)FLOAT_803e8198;
    if ((dVar20 <= dVar21) && (dVar20 = dVar21, (double)FLOAT_803e8164 < dVar21)) {
      dVar20 = (double)FLOAT_803e8164;
    }
    local_88 = (double)CONCAT44(0x43300000,(int)DAT_803dea4a ^ 0x80000000);
    dVar21 = (double)FUN_802945e0();
    piVar18[0x33] =
         (int)(float)((double)FLOAT_803e8164 * dVar21 +
                     (double)(float)((double)(float)piVar18[0x16] + dVar22));
    local_90 = (double)CONCAT44(0x43300000,(int)DAT_803dea48 ^ 0x80000000);
    dVar22 = (double)FUN_802945e0();
    piVar18[0x34] =
         (int)(float)((double)FLOAT_803e8194 * dVar22 +
                     (double)(float)((double)(float)piVar18[0x17] + dVar20));
    piVar18[0x35] = piVar18[0x18];
    piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803dc074);
    if ((float)piVar18[0x27] < FLOAT_803e816c) {
      piVar18[0x21] = 1;
      FUN_800201ac(0xd,0);
    }
    break;
  case 0x16:
    if (bVar1) {
      uVar11 = FUN_80022264(0,1);
      if (uVar11 == 0) {
        uVar4 = 0x472;
      }
      else {
        uVar4 = 0x471;
      }
      FUN_8000bb38((uint)psVar6,uVar4);
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccf0;
    }
    if (*(char *)(piVar18 + 0x2e) != '\0') {
      iVar16 = *piVar18;
      local_fc = ((float)piVar18[0x30] - *(float *)(iVar16 + 0xc)) * FLOAT_803dd0f0;
      local_f8 = ((float)piVar18[0x31] - *(float *)(iVar16 + 0x10)) * FLOAT_803dd0f0;
      local_f4 = ((float)piVar18[0x32] - *(float *)(iVar16 + 0x14)) * FLOAT_803dd0f0;
      local_f0 = local_fc;
      local_ec = local_f8;
      local_e8 = local_f4;
      FUN_8022db70(iVar16,&local_f0);
      fVar3 = -(FLOAT_803e81d4 * FLOAT_803dc074 - (float)piVar18[0x2a]);
      if (fVar3 < FLOAT_803e81d0) {
        fVar3 = FLOAT_803e81d0;
      }
      piVar18[0x2a] = (int)fVar3;
    }
    sVar5 = *(short *)(piVar18 + 0x28) - *psVar6;
    if (0x8000 < sVar5) {
      sVar5 = sVar5 + 1;
    }
    if (sVar5 < -0x8000) {
      sVar5 = sVar5 + -1;
    }
    iVar16 = (int)sVar5;
    if (iVar16 < 0) {
      iVar16 = -iVar16;
    }
    if (iVar16 < 2000) {
      cVar2 = *(char *)(*(int *)(piVar18[1] + 0xb8) + 0x23);
      if ((((cVar2 != '\x02') && (cVar2 != '\x01')) &&
          (cVar2 = *(char *)(*(int *)(piVar18[2] + 0xb8) + 0x23), cVar2 != '\x02')) &&
         (cVar2 != '\x01')) {
        piVar18[0x21] = 1;
      }
    }
    break;
  case 0x17:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,3,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032ccfc;
      piVar18[0x39] = (int)FLOAT_803e816c;
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xdf;
    }
    piVar18[0x39] = (int)((float)piVar18[0x39] + FLOAT_803dc074);
    if ((FLOAT_803e8210 < (float)piVar18[0x39]) && ((*(byte *)(piVar18 + 0x3a) >> 5 & 1) == 0)) {
      FUN_8000bb38((uint)psVar6,0x46f);
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xdf | 0x20;
    }
    if (FLOAT_803dd0f8 < *(float *)(psVar6 + 0x4c)) {
      dVar22 = (double)((float)piVar18[0x1c] - *(float *)(*piVar18 + 0x14));
      fVar3 = FLOAT_803e81d4 * FLOAT_803dc074 + (float)piVar18[0x2a];
      if (FLOAT_803e816c < fVar3) {
        fVar3 = FLOAT_803e816c;
      }
      piVar18[0x2a] = (int)fVar3;
      *(undefined *)(piVar18 + 0x2e) = 0;
      *(ushort *)(*piVar18 + 6) = *(ushort *)(*piVar18 + 6) & 0xbfff;
      iVar16 = FUN_8022db30(*piVar18);
      local_50 = (double)CONCAT44(0x43300000,(int)(short)iVar16 ^ 0x80000000);
      iVar16 = (int)(dVar22 * (double)FLOAT_803dd104 + (double)(float)(local_50 - DOUBLE_803e8130));
      local_58 = (longlong)iVar16;
      FUN_8022db40(*piVar18,(short)iVar16);
      local_9c = FLOAT_803e816c;
      local_98 = FLOAT_803e816c;
      local_ac = (float)(dVar22 * (double)FLOAT_803dd100);
      local_b4 = FLOAT_803e816c;
      local_b0 = FLOAT_803e816c;
      local_94 = local_ac;
      FUN_8022db70(*piVar18,&local_b4);
    }
    else {
      piVar18[0x30] = *(int *)(psVar6 + 6);
      piVar18[0x31] = (int)(*(float *)(psVar6 + 8) - FLOAT_803e8214);
      piVar18[0x32] = (int)(*(float *)(psVar6 + 10) - FLOAT_803e8218);
      iVar16 = *piVar18;
      local_114 = ((float)piVar18[0x30] - *(float *)(iVar16 + 0xc)) * FLOAT_803dd0fc;
      local_110 = ((float)piVar18[0x31] - *(float *)(iVar16 + 0x10)) * FLOAT_803dd0fc;
      local_10c = ((float)piVar18[0x32] - *(float *)(iVar16 + 0x14)) * FLOAT_803dd0fc;
      local_108 = local_114;
      local_104 = local_110;
      local_100 = local_10c;
      FUN_8022db70(iVar16,&local_108);
    }
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x18:
    if (bVar1) {
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,0x11,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd34;
      *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xdf;
    }
    if (FLOAT_803dd108 < *(float *)(psVar6 + 0x4c)) {
      dVar22 = (double)((float)piVar18[0x1c] - *(float *)(*piVar18 + 0x14));
      fVar3 = FLOAT_803e81ac * FLOAT_803dc074 + (float)piVar18[0x2a];
      if (FLOAT_803e816c < fVar3) {
        fVar3 = FLOAT_803e816c;
      }
      piVar18[0x2a] = (int)fVar3;
      *(undefined *)(piVar18 + 0x2e) = 0;
      *(ushort *)(*piVar18 + 6) = *(ushort *)(*piVar18 + 6) & 0xbfff;
      iVar16 = FUN_8022db30(*piVar18);
      local_50 = (double)CONCAT44(0x43300000,(int)(short)iVar16 ^ 0x80000000);
      iVar16 = (int)(dVar22 * (double)FLOAT_803dd114 + (double)(float)(local_50 - DOUBLE_803e8130));
      local_58 = (longlong)iVar16;
      FUN_8022db40(*piVar18,(short)iVar16);
      local_a8 = FLOAT_803e816c;
      local_a4 = FLOAT_803e816c;
      local_b8 = (float)(dVar22 * (double)FLOAT_803dd110);
      local_c0 = FLOAT_803e816c;
      local_bc = FLOAT_803e816c;
      local_a0 = local_b8;
      FUN_8022db70(*piVar18,&local_c0);
      if ((*(byte *)(piVar18 + 0x3a) >> 5 & 1) == 0) {
        FUN_8000bb38((uint)psVar6,0x46f);
        *(byte *)(piVar18 + 0x3a) = *(byte *)(piVar18 + 0x3a) & 0xdf | 0x20;
      }
    }
    else {
      iVar16 = *piVar18;
      local_12c = ((float)piVar18[0x30] - *(float *)(iVar16 + 0xc)) * FLOAT_803dd10c;
      local_128 = ((float)piVar18[0x31] - *(float *)(iVar16 + 0x10)) * FLOAT_803dd10c;
      local_124 = ((float)piVar18[0x32] - *(float *)(iVar16 + 0x14)) * FLOAT_803dd10c;
      local_120 = local_12c;
      local_11c = local_128;
      local_118 = local_124;
      FUN_8022db70(iVar16,&local_120);
    }
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x19:
  case 0x1a:
    if (bVar1) {
      FUN_8000bb38((uint)psVar6,0x4a6);
      iVar16 = *(int *)(psVar6 + 0x5c);
      FUN_8003042c((double)FLOAT_803e816c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar6,4,0,piVar9,pfVar14,uVar15,in_r9,in_r10);
      *(undefined4 *)(iVar16 + 100) = DAT_8032cd00;
    }
    if (FLOAT_803e8174 <= *(float *)(psVar6 + 0x4c)) {
      piVar18[0x21] = 1;
    }
    break;
  case 0x1b:
    if (bVar1) {
      FUN_800201ac(0x10,0);
      *(undefined2 *)(piVar18 + 0x26) = 0x1e;
      FUN_8022d9cc((undefined2 *)*piVar18);
      *(int *)(*piVar18 + 0x14) = piVar18[0x1c];
      piVar18[0x2a] = (int)FLOAT_803e816c;
    }
    piVar18[0x33] = piVar18[0x16];
    piVar18[0x34] = piVar18[0x17];
    piVar18[0x35] = piVar18[0x18];
    uVar11 = FUN_80020078(0x10);
    if ((uVar11 != 0) &&
       (sVar5 = *(short *)(piVar18 + 0x26), *(short *)(piVar18 + 0x26) = sVar5 + -1, sVar5 == 0)) {
      FUN_800201ac(0x10,0);
      piVar18[0x21] = 1;
    }
    break;
  case 0x1c:
    if (bVar1) {
      FUN_80240384(piVar18[3],1,'\0');
      FUN_80035ff8((int)psVar6);
      *(undefined2 *)(piVar18 + 0x26) = 0x3c;
      piVar18[0x27] = (int)FLOAT_803e8170;
      piVar18[0x33] = piVar18[0x16];
      piVar18[0x34] = piVar18[0x17];
      piVar18[0x35] = piVar18[0x18];
      fVar3 = FLOAT_803e816c;
      *(float *)(psVar6 + 0x12) = FLOAT_803e816c;
      *(float *)(psVar6 + 0x14) = fVar3;
      *(float *)(psVar6 + 0x16) = fVar3;
      piVar18[0x1d] = (int)FLOAT_803e8160;
      piVar18[0x1e] = (int)FLOAT_803e81c8;
    }
    piVar18[0x1a] = (int)((float)piVar18[0x1a] + FLOAT_803e81b4);
    fVar3 = (float)piVar18[0x1a];
    if (FLOAT_803e81cc < fVar3) {
      fVar3 = FLOAT_803e81cc;
    }
    piVar18[0x1a] = (int)fVar3;
    for (bVar17 = 0; bVar17 < 6; bVar17 = bVar17 + 1) {
      uVar11 = FUN_80020078(bVar17 + 0x108);
      if (uVar11 != 0) {
        *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
        goto LAB_8023e554;
      }
    }
    *(ushort *)((int)piVar18 + 0xa6) = *(short *)((int)piVar18 + 0xa6) - (ushort)DAT_803dc070;
    if (*(short *)((int)piVar18 + 0xa6) < 1) {
      uVar11 = FUN_80022264(0,5);
      FUN_800201ac(uVar11 + 0x108,1);
      *(undefined2 *)((int)piVar18 + 0xa6) = 0x3c;
    }
LAB_8023e554:
    *(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070;
    if (*(short *)(piVar18 + 0x26) < 0) {
      piVar18[0x27] = (int)((float)piVar18[0x27] - FLOAT_803e8174);
      if (FLOAT_803e816c <= (float)piVar18[0x27]) {
        uVar11 = FUN_80022264(0x14,0x1e);
        *(short *)(piVar18 + 0x26) = (short)uVar11;
        local_78 = (double)(longlong)(int)-FLOAT_803dd0d8;
        local_80 = (longlong)(int)FLOAT_803dd0d8;
        uVar11 = FUN_80022264((int)-FLOAT_803dd0d8,(int)FLOAT_803dd0d8);
        local_88 = (double)CONCAT44(0x43300000,uVar11 ^ 0x80000000);
        piVar18[0x33] = (int)((float)piVar18[0x16] + (float)(local_88 - DOUBLE_803e8130));
        local_90 = (double)(longlong)(int)-FLOAT_803dd0dc;
        local_70 = (longlong)(int)FLOAT_803dd0dc;
        uStack_64 = FUN_80022264((int)-FLOAT_803dd0dc,(int)FLOAT_803dd0dc);
        uStack_64 = uStack_64 ^ 0x80000000;
        local_68 = 0x43300000;
        piVar18[0x34] =
             (int)((float)piVar18[0x17] +
                  (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e8130));
        local_60 = (longlong)(int)-FLOAT_803dd0e0;
        local_58 = (longlong)(int)FLOAT_803dd0e0;
        uVar11 = FUN_80022264((int)-FLOAT_803dd0e0,(int)FLOAT_803dd0e0);
        local_50 = (double)CONCAT44(0x43300000,uVar11 ^ 0x80000000);
        piVar18[0x35] = (int)((float)piVar18[0x18] + (float)(local_50 - DOUBLE_803e8130));
      }
      else {
        *(char *)(piVar18 + 0x2b) = *(char *)(piVar18 + 0x2b) + '\x01';
        if (*(byte *)(piVar18 + 0x2b) < 4) {
          piVar18[0x22] = 0x1d;
        }
        else {
          piVar18[0x1f] = 5;
          piVar18[0x20] = 5;
          *(undefined *)(piVar18 + 0x2b) = 0;
          piVar18[0x22] = 0x12;
          FUN_80240384(piVar18[3],0,'\0');
          FUN_80036018((int)psVar6);
        }
      }
    }
    if ((*(byte *)((int)piVar18 + 0xad) & 8) != 0) {
      FUN_8011f638(2);
      FUN_800201ac(1,1);
      uVar19 = FUN_800201ac(0x4b1,1);
      piVar18[0x22] = 0x1e;
      FUN_80043604(0,0,1);
      FUN_8004832c(0xb);
      FUN_80043938(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8000a538((int *)0xf3,0);
    }
    dVar22 = (double)(float)piVar18[0x1a];
    piVar9 = (int *)FUN_8002b660((int)psVar6);
    iVar7 = *piVar9;
    dVar22 = (double)(longlong)(int)((double)FLOAT_803e814c * dVar22);
    for (iVar16 = 0; iVar16 < (int)(uint)*(byte *)(iVar7 + 0xf8); iVar16 = iVar16 + 1) {
      iVar10 = FUN_800284e8(iVar7,iVar16);
      *(char *)(iVar10 + 0x43) = SUB81(dVar22,0);
      local_50 = dVar22;
    }
    break;
  case 0x1d:
    if (bVar1) {
      FUN_80240384(piVar18[3],1,'\0');
      FUN_80035ff8((int)psVar6);
      *(short *)(piVar18 + 0x26) = (short)DAT_803dd0ec;
      piVar18[0x33] = *(int *)(*piVar18 + 0xc);
      piVar18[0x34] = (int)(*(float *)(*piVar18 + 0x10) + FLOAT_803dd0e4);
      piVar18[0x35] = (int)(*(float *)(*piVar18 + 0x14) + FLOAT_803dd0e8);
      fVar3 = FLOAT_803e816c;
      *(float *)(psVar6 + 0x12) = FLOAT_803e816c;
      *(float *)(psVar6 + 0x14) = fVar3;
      *(float *)(psVar6 + 0x16) = fVar3;
      uVar11 = FUN_80022264(0,1);
      if (uVar11 == 0) {
        uVar4 = 0x472;
      }
      else {
        uVar4 = 0x471;
      }
      FUN_8000bb38((uint)psVar6,uVar4);
    }
    *(ushort *)(piVar18 + 0x26) = *(short *)(piVar18 + 0x26) - (ushort)DAT_803dc070;
    if (*(short *)(piVar18 + 0x26) < 0) {
      piVar18[0x22] = 0x1c;
    }
    break;
  case 0x1e:
    uVar11 = FUN_80020078(2);
    if (((uVar11 != 0) || (uVar11 = FUN_80020078(3), uVar11 != 0)) ||
       (uVar11 = FUN_80020078(4), uVar11 != 0)) {
      FUN_800201ac(0x405,0);
      uVar19 = (**(code **)(*DAT_803dd72c + 0x44))(0xb,7);
      uVar13 = 1;
      FUN_80043604(0,0,1);
      iVar16 = FUN_8004832c(0xb);
      FUN_80043070(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar16);
      uVar12 = FUN_8004832c(0xb);
      FUN_80043658(uVar12,1);
      FUN_80055464(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4e,'\0',uVar13,
                   piVar9,pfVar14,uVar15,in_r9,in_r10);
      piVar18[0x1a] = (int)FLOAT_803e816c;
      piVar18[0x22] = 0x1f;
    }
  }
  local_134 = FLOAT_803e821c + (float)piVar18[0x2a];
  (**(code **)(*DAT_803dd6d0 + 0x60))(&local_134,4);
  *(float *)(psVar6 + 0x12) =
       (float)piVar18[0x1d] * ((float)piVar18[0x33] - *(float *)(psVar6 + 6)) +
       *(float *)(psVar6 + 0x12);
  *(float *)(psVar6 + 0x14) =
       (float)piVar18[0x1d] * ((float)piVar18[0x34] - *(float *)(psVar6 + 8)) +
       *(float *)(psVar6 + 0x14);
  *(float *)(psVar6 + 0x16) =
       (float)piVar18[0x1d] * ((float)piVar18[0x35] - *(float *)(psVar6 + 10)) +
       *(float *)(psVar6 + 0x16);
  *(float *)(psVar6 + 0x12) = *(float *)(psVar6 + 0x12) * (float)piVar18[0x1e];
  *(float *)(psVar6 + 0x14) = *(float *)(psVar6 + 0x14) * (float)piVar18[0x1e];
  *(float *)(psVar6 + 0x16) = *(float *)(psVar6 + 0x16) * (float)piVar18[0x1e];
  *(float *)(psVar6 + 6) = *(float *)(psVar6 + 6) + *(float *)(psVar6 + 0x12);
  *(float *)(psVar6 + 8) = *(float *)(psVar6 + 8) + *(float *)(psVar6 + 0x14);
  *(float *)(psVar6 + 10) = *(float *)(psVar6 + 10) + *(float *)(psVar6 + 0x16);
  dVar22 = (double)FLOAT_803e816c;
  if (dVar22 == (double)(float)piVar18[0x38]) {
    if (*(char *)(piVar18 + 0x2e) == '\0') {
      piVar18[0x38] = (int)(FLOAT_803dd118 * ((float)piVar18[0x1c] - *(float *)(*piVar18 + 0x14)));
    }
    else {
      FUN_8023ad9c((double)FLOAT_803dd11c,(double)FLOAT_803dd120,dVar22,piVar18);
    }
  }
  if (*(int *)(*piVar18 + 0xc0) == 0) {
    local_cc = (float)piVar18[0x36];
    local_c8 = piVar18[0x37];
    local_c4 = piVar18[0x38];
    FUN_8022db90(*piVar18,&local_cc);
  }
  sVar5 = *(short *)(piVar18 + 0x28) - *psVar6;
  if (0x8000 < sVar5) {
    sVar5 = sVar5 + 1;
  }
  if (sVar5 < -0x8000) {
    sVar5 = sVar5 + -1;
  }
  *(short *)((int)piVar18 + 0xa2) =
       *(short *)((int)piVar18 + 0xa2) +
       (short)(((int)sVar5 / DAT_803dd098 - (int)*(short *)((int)piVar18 + 0xa2)) / DAT_803dd09c);
  *(short *)(piVar18 + 0x29) =
       *(short *)(piVar18 + 0x29) +
       (short)((-(int)psVar6[1] / DAT_803dd098 - (int)*(short *)(piVar18 + 0x29)) / DAT_803dd09c);
  *psVar6 = *psVar6 + *(short *)((int)piVar18 + 0xa2);
  psVar6[1] = psVar6[1] + *(short *)(piVar18 + 0x29);
  dVar21 = (double)FLOAT_803dc074;
  FUN_8002fb40((double)(float)piVar18[0x19],dVar21);
  uVar19 = FUN_8023aadc();
  FUN_8023af74(uVar19,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,(int)psVar6,(int)piVar18
              );
  iVar16 = piVar18[5];
  if (iVar16 != 0) {
    fVar3 = *(float *)(iVar16 + 0x14);
    *(float *)(iVar16 + 0x14) = (float)((double)fVar3 - (double)FLOAT_803e8170);
    piVar18[0x25] = piVar18[0x25] - (uint)DAT_803dc070;
    if (piVar18[0x25] < 0) {
      FUN_8002cc9c((double)fVar3,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,piVar18[5]);
      piVar18[0x25] = 0;
      piVar18[5] = 0;
    }
  }
  if (piVar18[0x1f] < 6) {
    local_138 = FLOAT_803e8128;
    iVar16 = FUN_800381d8(psVar6,0x7e5,&local_138);
    if (iVar16 != 0) {
      if (*(int *)(iVar16 + 0xc0) != 0) {
        iVar16 = *(int *)(iVar16 + 0xc0);
      }
      if ((*(short *)(iVar16 + 0x44) != 0x10) ||
         (iVar7 = FUN_800805cc(*(int *)(iVar16 + 0xb8)), iVar7 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 8) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0xc) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0x10) = *(undefined4 *)(psVar6 + 10);
      }
    }
    local_13c = FLOAT_803e8128;
    iVar16 = FUN_800381d8(psVar6,0x1e,&local_13c);
    if (iVar16 != 0) {
      if (*(int *)(iVar16 + 0xc0) != 0) {
        iVar16 = *(int *)(iVar16 + 0xc0);
      }
      if ((*(short *)(iVar16 + 0x44) != 0x10) ||
         (iVar7 = FUN_800805cc(*(int *)(iVar16 + 0xb8)), iVar7 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 8) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0xc) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0x10) = *(undefined4 *)(psVar6 + 10);
      }
    }
    local_140 = FLOAT_803e8128;
    iVar16 = FUN_800381d8(psVar6,0x76f,&local_140);
    if (iVar16 != 0) {
      if (*(int *)(iVar16 + 0xc0) != 0) {
        iVar16 = *(int *)(iVar16 + 0xc0);
      }
      if ((*(short *)(iVar16 + 0x44) != 0x10) ||
         (iVar7 = FUN_800805cc(*(int *)(iVar16 + 0xb8)), iVar7 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 8) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0xc) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0x10) = *(undefined4 *)(psVar6 + 10);
      }
    }
    local_144 = FLOAT_803e8128;
    iVar16 = FUN_800381d8(psVar6,0x814,&local_144);
    if (iVar16 != 0) {
      if (*(int *)(iVar16 + 0xc0) != 0) {
        iVar16 = *(int *)(iVar16 + 0xc0);
      }
      if ((*(short *)(iVar16 + 0x44) != 0x10) ||
         (iVar7 = FUN_800805cc(*(int *)(iVar16 + 0xb8)), iVar7 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 8) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0xc) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0x10) = *(undefined4 *)(psVar6 + 10);
      }
    }
    local_148 = FLOAT_803e8128;
    iVar16 = FUN_800381d8(psVar6,0x6cf,&local_148);
    if (iVar16 != 0) {
      if (*(int *)(iVar16 + 0xc0) != 0) {
        iVar16 = *(int *)(iVar16 + 0xc0);
      }
      if ((*(short *)(iVar16 + 0x44) != 0x10) ||
         (iVar7 = FUN_800805cc(*(int *)(iVar16 + 0xb8)), iVar7 != 0x598)) {
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 8) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0xc) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(*(int *)(iVar16 + 0x4c) + 0x10) = *(undefined4 *)(psVar6 + 10);
      }
    }
  }
LAB_8023f60c:
  FUN_80286880();
  return;
}

