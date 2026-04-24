// Function: FUN_8010c0d8
// Entry: 8010c0d8
// Size: 3204 bytes

/* WARNING: Removing unreachable block (ram,0x8010cd34) */
/* WARNING: Removing unreachable block (ram,0x8010cd24) */
/* WARNING: Removing unreachable block (ram,0x8010cd1c) */
/* WARNING: Removing unreachable block (ram,0x8010cd2c) */
/* WARNING: Removing unreachable block (ram,0x8010cd3c) */

void FUN_8010c0d8(void)

{
  float fVar1;
  short sVar2;
  float fVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  float local_128;
  float local_124;
  float local_120;
  float local_11c;
  undefined auStack280 [4];
  undefined auStack276 [4];
  undefined auStack272 [4];
  float local_10c;
  float local_108;
  float local_104;
  undefined auStack256 [12];
  undefined auStack244 [116];
  double local_80;
  undefined4 local_78;
  uint uStack116;
  double local_70;
  undefined auStack72 [16];
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  psVar4 = (short *)FUN_802860dc();
  iVar5 = FUN_8000faac();
  if (*(char *)((int)DAT_803dd568 + 0x12) == '\0') {
    iVar9 = *(int *)(psVar4 + 0x52);
    if ((*(short *)(iVar9 + 0x44) == 1) && (iVar6 = FUN_80296328(iVar9), iVar6 == 0)) {
      if (*(int *)(psVar4 + 0x8e) != 0) {
        if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
           ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cd1c;
        (**(code **)(*DAT_803dca50 + 0x48))(0);
      }
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
    }
    else {
      iVar6 = *(int *)(psVar4 + 0x8e);
      if ((iVar6 == 0) ||
         (((*(ushort *)(iVar6 + 0xb0) & 0x40) != 0 || ((*(byte *)(iVar6 + 0xaf) & 0x28) != 0)))) {
        if (iVar6 != 0) {
          if (((*(byte *)(iVar6 + 0xaf) & 0x40) != 0) || ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)
             ) goto LAB_8010cd1c;
          (**(code **)(*DAT_803dca50 + 0x48))(0);
        }
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
      }
      else {
        iVar10 = *(int *)(iVar6 + 0x74);
        if (iVar10 != 0) {
          local_80 = (double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(*(int *)(*(int *)(iVar6 + 0x50) + 0x40) + 0xd)
                                      << 2 ^ 0x80000000);
          dVar16 = (double)(float)(local_80 - DOUBLE_803e1938);
          uVar7 = FUN_80014e70(0);
          if (((uVar7 & 0x200) == 0) || (iVar8 = FUN_8029630c(iVar9), iVar8 == 0)) {
            local_120 = FLOAT_803e18d0 + *(float *)(iVar9 + 0x1c);
            sVar2 = *(short *)(iVar6 + 0x44);
            if ((sVar2 == 0x1c) || ((sVar2 == 0x6d || (sVar2 == 0x2a)))) {
              if (*(short *)(iVar6 + 0x46) == 0x200) {
                local_120 = local_120 + FLOAT_803e18d0;
              }
              if (*(byte *)(*(int *)(iVar6 + 0x50) + 0x72) < 2) {
                local_124 = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0xc) -
                            *(float *)(iVar9 + 0x18);
                local_11c = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x10) -
                            local_120;
                local_128 = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x14) -
                            *(float *)(iVar9 + 0x20);
              }
              else {
                FUN_8010bf08(psVar4,&local_124,&local_11c,&local_128,&local_120);
              }
            }
            else {
              local_120 = FLOAT_803e18d0 + *(float *)(iVar9 + 0x1c);
              local_124 = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0xc) -
                          *(float *)(iVar9 + 0x18);
              local_11c = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x10) -
                          local_120;
              local_128 = *(float *)(iVar10 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x14) -
                          *(float *)(iVar9 + 0x20);
            }
            dVar12 = (double)FUN_802931a0((double)(local_124 * local_124 + local_128 * local_128));
            *(undefined *)((int)psVar4 + 0x13b) = 0x30;
            *(undefined *)(psVar4 + 0x9e) = 1;
            if (dVar12 <= dVar16) {
              FUN_80296bd4(iVar9,auStack280,auStack276,auStack272);
              dVar18 = (double)(FLOAT_803e18d4 * local_124 + *(float *)(iVar9 + 0x18));
              dVar17 = (double)(FLOAT_803e18d8 + local_120);
              dVar16 = (double)(FLOAT_803e18d4 * local_128 + *(float *)(iVar9 + 0x20));
              uVar7 = FUN_800217c0();
              iVar10 = (int)*psVar4 - (0x8000 - ((uVar7 & 0xffff) + 0x8000) & 0xffff);
              if (0x8000 < iVar10) {
                iVar10 = iVar10 + -0xffff;
              }
              if (iVar10 < -0x8000) {
                iVar10 = iVar10 + 0xffff;
              }
              if (iVar10 < 0x2329) {
                if (iVar10 < -9000) {
                  local_70 = (double)CONCAT44(0x43300000,iVar10 + 9000U ^ 0x80000000);
                  dVar13 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                                (double)FLOAT_803e18dc,(double)FLOAT_803db414);
                  uStack116 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1938) - dVar13);
                  local_80 = (double)(longlong)iVar8;
                  *psVar4 = (short)iVar8;
                }
              }
              else {
                local_80 = (double)CONCAT44(0x43300000,iVar10 - 9000U ^ 0x80000000);
                dVar13 = (double)FUN_80021370((double)(float)(local_80 - DOUBLE_803e1938),
                                              (double)FLOAT_803e18dc,(double)FLOAT_803db414);
                uStack116 = (int)*psVar4 ^ 0x80000000;
                local_78 = 0x43300000;
                *psVar4 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                                      DOUBLE_803e1938) - dVar13);
              }
              if ((iVar10 < 3000) && (0 < iVar10)) {
                if (((DAT_803dd56c < 3000) && (iVar10 < 1000)) && (iVar10 < DAT_803dd56c)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar10 - 3000U ^ 0x80000000);
                  dVar13 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                                (double)FLOAT_803e18e0,(double)FLOAT_803db414);
                  uStack116 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1938) + dVar13);
                  local_80 = (double)(longlong)iVar8;
                  *psVar4 = (short)iVar8;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar10 ^ 0x80000000);
                  dVar13 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                                (double)FLOAT_803e18e0,(double)FLOAT_803db414);
                  uStack116 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1938) + dVar13);
                  local_80 = (double)(longlong)iVar8;
                  *psVar4 = (short)iVar8;
                }
              }
              else if ((-3000 < iVar10) && (iVar10 < 0)) {
                if (((DAT_803dd56c < -2999) || (iVar10 < -999)) || (iVar10 <= DAT_803dd56c)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar10 - 3000U ^ 0x80000000);
                  dVar13 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                                (double)FLOAT_803e18e0,(double)FLOAT_803db414);
                  uStack116 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1938) + dVar13);
                  local_80 = (double)(longlong)iVar8;
                  *psVar4 = (short)iVar8;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar10 ^ 0x80000000);
                  dVar13 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                                (double)FLOAT_803e18e0,(double)FLOAT_803db414);
                  uStack116 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1938) + dVar13);
                  local_80 = (double)(longlong)iVar8;
                  *psVar4 = (short)iVar8;
                }
              }
              iVar8 = iVar10;
              if (iVar10 < 0) {
                iVar8 = -iVar10;
              }
              if (9000 < iVar8) {
                iVar8 = 9000;
              }
              local_70 = (double)CONCAT44(0x43300000,9000U - iVar8 ^ 0x80000000);
              dVar15 = (double)((float)(local_70 - DOUBLE_803e1938) / FLOAT_803e18e4);
              DAT_803dd56c = iVar10;
              dVar13 = (double)FUN_80021370((double)(FLOAT_803e18e8 - DAT_803dd568[1]),
                                            (double)FLOAT_803e18ec,(double)FLOAT_803db414);
              DAT_803dd568[1] = (float)((double)DAT_803dd568[1] + dVar13);
              dVar13 = (double)FUN_80021370((double)((FLOAT_803e18f0 +
                                                     (float)((double)FLOAT_803e18c0 - dVar15)) /
                                                     FLOAT_803e18f4 - DAT_803dd568[2]),
                                            (double)FLOAT_803e18f8,(double)FLOAT_803db414);
              DAT_803dd568[2] = (float)((double)DAT_803dd568[2] + dVar13);
              uStack116 = (int)*psVar4 ^ 0x80000000;
              local_78 = 0x43300000;
              dVar13 = (double)FUN_80293e80((double)((FLOAT_803e18fc *
                                                     (float)((double)CONCAT44(0x43300000,uStack116)
                                                            - DOUBLE_803e1938)) / FLOAT_803e1900));
              local_80 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
              dVar15 = (double)FUN_80294204((double)((FLOAT_803e18fc *
                                                     (float)(local_80 - DOUBLE_803e1938)) /
                                                    FLOAT_803e1900));
              local_10c = (float)(dVar18 + (double)(float)((double)*DAT_803dd568 * dVar13));
              local_104 = (float)(dVar16 - (double)(float)((double)*DAT_803dd568 * dVar15));
              local_11c = (local_120 - local_11c * FLOAT_803e1904) + DAT_803dd568[1];
              dVar16 = (double)FUN_80021370((double)(*(float *)(psVar4 + 0xe) - local_11c),
                                            (double)FLOAT_803e1908,(double)FLOAT_803db414);
              local_108 = (float)((double)*(float *)(psVar4 + 0xe) - dVar16);
              FUN_80247754(&local_10c,psVar4 + 0xc,auStack256);
              dVar16 = (double)FUN_802477f0(auStack256);
              if ((double)FLOAT_803e18c4 < dVar16) {
                FUN_80247794(auStack256,auStack256);
              }
              dVar18 = dVar16;
              if (*(float *)(psVar4 + 0x7a) <= FLOAT_803e18c4) {
                fVar1 = *(float *)(iVar9 + 0x8c) - *(float *)(iVar9 + 0x18);
                fVar3 = *(float *)(iVar9 + 0x94) - *(float *)(iVar9 + 0x20);
                dVar18 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar3 * fVar3));
                dVar13 = (double)(float)(dVar18 * (double)(FLOAT_803e190c * FLOAT_803db414));
                if (dVar13 < DOUBLE_803e1918) {
                  dVar13 = (double)FLOAT_803e1910;
                }
                dVar18 = (double)FLOAT_803e18c4;
                if ((dVar18 <= dVar16) && (dVar18 = dVar16, dVar13 < dVar16)) {
                  dVar18 = dVar13;
                }
              }
              dVar16 = (double)FLOAT_803e18c4;
              if ((dVar16 <= dVar18) && (dVar16 = dVar18, (double)FLOAT_803e18d0 < dVar18)) {
                dVar16 = (double)FLOAT_803e18d0;
              }
              FUN_80247778(dVar16,auStack256,auStack256);
              FUN_80247730(psVar4 + 0xc,auStack256,psVar4 + 0xc);
              FUN_80103524((double)FLOAT_803e18cc,auStack280,psVar4 + 0xc,psVar4 + 0xc,auStack244,3,
                           1,1);
              fVar3 = *(float *)(iVar5 + 0xc) -
                      (FLOAT_803e18f8 * local_124 + *(float *)(iVar9 + 0x18));
              local_11c = (float)((double)*(float *)(iVar5 + 0x10) - dVar17);
              fVar1 = *(float *)(iVar5 + 0x14) -
                      (FLOAT_803e18f8 * local_128 + *(float *)(iVar9 + 0x20));
              uVar14 = FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1));
              uVar7 = FUN_800217c0((double)local_11c,uVar14);
              uVar7 = (uVar7 & 0xffff) - ((int)psVar4[1] & 0xffffU);
              if (0x8000 < (int)uVar7) {
                uVar7 = uVar7 - 0xffff;
              }
              if ((int)uVar7 < -0x8000) {
                uVar7 = uVar7 + 0xffff;
              }
              local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              dVar16 = (double)FUN_80021370((double)(float)(local_70 - DOUBLE_803e1938),
                                            (double)FLOAT_803e1920,(double)FLOAT_803db414);
              uStack116 = (int)psVar4[1] ^ 0x80000000;
              local_78 = 0x43300000;
              iVar5 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e1938
                                           ) + dVar16);
              local_80 = (double)(longlong)iVar5;
              psVar4[1] = (short)iVar5;
              fVar1 = (float)((double)FLOAT_803e1924 + dVar12);
              if ((float)((double)FLOAT_803e1924 + dVar12) < FLOAT_803e1928) {
                fVar1 = FLOAT_803e1928;
              }
              if (FLOAT_803e192c < fVar1) {
                fVar1 = FLOAT_803e192c;
              }
              dVar12 = (double)(fVar1 - *DAT_803dd568);
              dVar16 = (double)FUN_80292b44((double)FLOAT_803e18ec,(double)FLOAT_803db414);
              fVar1 = (float)(dVar12 * dVar16);
              fVar3 = FLOAT_803e18d8 * FLOAT_803db414;
              if ((fVar1 <= fVar3) && (fVar3 = fVar1, fVar1 < FLOAT_803e1930 * FLOAT_803db414)) {
                fVar3 = FLOAT_803e1930 * FLOAT_803db414;
              }
              *DAT_803dd568 = *DAT_803dd568 + fVar3;
              FUN_8005507c((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                           (double)*(float *)(iVar6 + 0x20),1,0);
              if (FLOAT_803e18c4 == *(float *)(psVar4 + 0x7a)) {
                *(byte *)((int)psVar4 + 0x143) = *(byte *)((int)psVar4 + 0x143) & 0x7f | 0x80;
              }
              FUN_8000e034((double)*(float *)(psVar4 + 0xc),(double)*(float *)(psVar4 + 0xe),
                           (double)*(float *)(psVar4 + 0x10),psVar4 + 6,psVar4 + 8,psVar4 + 10,
                           *(undefined4 *)(psVar4 + 0x18));
            }
            else {
              if (*(int *)(psVar4 + 0x8e) != 0) {
                if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                   ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cd1c;
                (**(code **)(*DAT_803dca50 + 0x48))(0);
              }
              (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
            }
          }
          else {
            if (*(int *)(psVar4 + 0x8e) != 0) {
              if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                 ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cd1c;
              (**(code **)(*DAT_803dca50 + 0x48))(0);
            }
            (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
      }
    }
  }
  else {
    if (*(int *)(psVar4 + 0x8e) != 0) {
      if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
         ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cd1c;
      (**(code **)(*DAT_803dca50 + 0x48))(0);
    }
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
  }
LAB_8010cd1c:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  FUN_80286128();
  return;
}

