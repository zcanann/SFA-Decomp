// Function: FUN_8008dd50
// Entry: 8008dd50
// Size: 2824 bytes

/* WARNING: Removing unreachable block (ram,0x8008e830) */
/* WARNING: Removing unreachable block (ram,0x8008e820) */
/* WARNING: Removing unreachable block (ram,0x8008e810) */
/* WARNING: Removing unreachable block (ram,0x8008e800) */
/* WARNING: Removing unreachable block (ram,0x8008e7f8) */
/* WARNING: Removing unreachable block (ram,0x8008e808) */
/* WARNING: Removing unreachable block (ram,0x8008e818) */
/* WARNING: Removing unreachable block (ram,0x8008e828) */
/* WARNING: Removing unreachable block (ram,0x8008e838) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_8008dd50(void)

{
  int iVar1;
  int iVar2;
  float fVar3;
  ushort uVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  float *pfVar9;
  int iVar10;
  int *piVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined8 in_f23;
  undefined8 in_f24;
  undefined8 in_f25;
  undefined8 in_f26;
  double dVar16;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar17;
  undefined8 in_f29;
  double dVar18;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  double dVar21;
  byte local_108;
  byte local_107;
  byte local_106 [2];
  undefined2 local_104;
  undefined local_102;
  float local_100;
  float local_fc;
  float local_f8;
  undefined4 local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  short local_e4;
  undefined2 local_e2;
  undefined2 local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  double local_c8;
  double local_c0;
  double local_b8;
  double local_b0;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  FUN_802860d8();
  local_fc = DAT_802c1f98;
  local_f8 = DAT_802c1f9c;
  local_f4 = DAT_802c1fa0;
  dVar20 = (double)FLOAT_803df108;
  local_100 = FLOAT_803df108;
  local_104 = DAT_803e8460;
  local_102 = DAT_803e8462;
  dVar17 = dVar20;
  dVar15 = dVar20;
  dVar14 = dVar20;
  dVar13 = dVar20;
  FUN_800898c8(0,local_106,&local_107,&local_108);
  if (DAT_803db758 != '\0') {
    DAT_8039a7b8 = FLOAT_803df108;
    DAT_8039a7bc = FLOAT_803df108;
    DAT_8039a7c0 = FLOAT_803df114;
    DAT_8039a7c4 = FLOAT_803df150;
    DAT_8039a7c8 = FLOAT_803df108;
    DAT_8039a7cc = FLOAT_803df154;
    DAT_8039a7d0 = FLOAT_803df158;
    DAT_8039a7d4 = FLOAT_803df108;
    DAT_8039a7d8 = FLOAT_803df108;
    DAT_8039a7dc = FLOAT_803df150;
    DAT_8039a7e0 = FLOAT_803df108;
    DAT_8039a7e4 = FLOAT_803df150;
    DAT_8039a7e8 = FLOAT_803df108;
    DAT_8039a7ec = FLOAT_803df108;
    DAT_8039a7f0 = FLOAT_803df158;
    DAT_8039a7f4 = FLOAT_803df154;
    DAT_8039a7f8 = FLOAT_803df108;
    DAT_8039a7fc = FLOAT_803df150;
    DAT_8039a800 = FLOAT_803df114;
    DAT_8039a804 = FLOAT_803df108;
    DAT_8039a808 = FLOAT_803df108;
    DAT_8039a80c = FLOAT_803df154;
    DAT_8039a810 = FLOAT_803df108;
    DAT_8039a814 = FLOAT_803df154;
    DAT_803db758 = '\0';
  }
  psVar5 = (short *)FUN_8000faac();
  local_f0 = FLOAT_803df108;
  local_ec = FLOAT_803df108;
  local_e8 = FLOAT_803df158;
  local_d8 = FLOAT_803df108;
  local_d4 = FLOAT_803df108;
  local_d0 = FLOAT_803df108;
  local_dc = FLOAT_803df114;
  local_e4 = -*psVar5;
  local_e0 = 0;
  local_e2 = 0;
  FUN_80021ac8(&local_e4,&local_f0);
  iVar10 = 0;
  piVar11 = &DAT_803dd184;
  do {
    fVar3 = FLOAT_803df118;
    if ((*piVar11 != 0) && (*(char *)(*piVar11 + 0x317) != '\0')) {
      DAT_803db750 = 0;
      iVar6 = *piVar11;
      if (*(int *)(iVar6 + 0x48) == 0) {
        if (*(int *)(iVar6 + 0x44) != 0) {
          *(float *)(iVar6 + 0x30c) = *(float *)(iVar6 + 0x310) / FLOAT_803df118;
          iVar6 = *piVar11;
          if ((*(ushort *)(iVar6 + 4) & 1) == 0) {
            *(float *)(iVar6 + 0x310) =
                 -(FLOAT_803db414 * *(float *)(iVar6 + 0x58) - *(float *)(iVar6 + 0x310));
            if (*(float *)(*piVar11 + 0x310) < FLOAT_803df108) {
              *(float *)(*piVar11 + 0x310) = FLOAT_803df108;
            }
          }
        }
      }
      else if ((*(ushort *)(iVar6 + 4) & 1) == 0) {
        *(float *)(iVar6 + 0x310) = FLOAT_803df118 * *(float *)(iVar6 + 0x30c);
        if (fVar3 < *(float *)(*piVar11 + 0x310)) {
          *(float *)(*piVar11 + 0x310) = fVar3;
        }
      }
      dVar18 = dVar15;
      dVar19 = dVar14;
      dVar21 = dVar13;
      if ((*(ushort *)(*piVar11 + 4) & 0x100) != 0) {
        FUN_8008d088(iVar10);
        dVar18 = dVar15;
        dVar19 = dVar14;
        dVar21 = dVar13;
      }
      iVar6 = *piVar11;
      if ((*(ushort *)(iVar6 + 4) & 0x10) == 0) {
        if ((*(ushort *)(iVar6 + 6) & 0x20) == 0) {
          iVar6 = 0;
          pfVar9 = &DAT_8039a7b8;
          dVar14 = (double)FLOAT_803df178;
          dVar13 = (double)FLOAT_803df170;
          dVar16 = (double)FLOAT_803df144;
          dVar15 = DOUBLE_803df130;
          do {
            uVar8 = FUN_800217c0((double)*pfVar9,(double)pfVar9[2]);
            uVar7 = FUN_800217c0((double)local_f0,(double)local_e8);
            uVar8 = (uVar8 & 0xffff) - (uVar7 & 0xffff);
            if ((int)uVar8 < 0) {
              uVar8 = -uVar8;
            }
            if (0x7fff < (int)uVar8) {
              uVar8 = 0xffff - uVar8;
            }
            local_c8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            fVar3 = (float)((double)(float)((double)(float)((double)(float)(dVar14 - (double)(float)
                                                  (local_c8 - dVar15)) / dVar14) - dVar13) / dVar16)
            ;
            if (fVar3 <= local_fc) {
              if (local_f8 < fVar3) {
                local_104 = local_104 & 0xff00 | (ushort)(byte)iVar6;
                local_f8 = fVar3;
              }
            }
            else {
              if (local_f8 < local_fc) {
                local_f8 = local_fc;
                local_104 = local_104 >> 8;
              }
              local_104 = local_104 & 0xff | (ushort)(byte)iVar6 << 8;
              local_fc = fVar3;
            }
            pfVar9 = pfVar9 + 3;
            iVar6 = iVar6 + 1;
          } while (iVar6 < 8);
          dVar15 = (double)local_fc;
          if ((double)FLOAT_803df108 < dVar15) {
            iVar6 = *piVar11 + (uint)local_104._0_1_ * 4;
            dVar21 = (double)(float)((double)*(float *)(iVar6 + 0x70) * dVar15 + dVar21);
            dVar19 = (double)(float)((double)*(float *)(iVar6 + 0x9c) * dVar15 + dVar19);
            dVar18 = (double)(float)((double)*(float *)(iVar6 + 200) * dVar15 + dVar18);
            dVar17 = (double)(float)((double)*(float *)(*piVar11 + (uint)local_104._0_1_ * 4 + 0x1fc
                                                       ) * dVar15 + dVar17);
            dVar20 = (double)(float)((double)*(float *)(iVar6 + 0x228) * dVar15 + dVar20);
          }
          dVar15 = (double)local_f8;
          if ((double)FLOAT_803df108 < dVar15) {
            iVar6 = *piVar11 + (uint)(byte)local_104 * 4;
            dVar21 = (double)(float)((double)*(float *)(iVar6 + 0x70) * dVar15 + dVar21);
            dVar19 = (double)(float)((double)*(float *)(iVar6 + 0x9c) * dVar15 + dVar19);
            dVar18 = (double)(float)((double)*(float *)(iVar6 + 200) * dVar15 + dVar18);
            dVar17 = (double)(float)((double)*(float *)(*piVar11 + (uint)(byte)local_104 * 4 + 0x1fc
                                                       ) * dVar15 + dVar17);
            dVar20 = (double)(float)((double)*(float *)(iVar6 + 0x228) * dVar15 + dVar20);
          }
        }
        else {
          (**(code **)(*DAT_803dca58 + 0x14))(&local_100);
          fVar3 = local_100 / FLOAT_803df15c;
          if (local_100 / FLOAT_803df15c < FLOAT_803df108) {
            fVar3 = FLOAT_803df108;
          }
          if (FLOAT_803df114 < fVar3) {
            fVar3 = FLOAT_803df114;
          }
          if (FLOAT_803df160 < fVar3) {
            if (FLOAT_803df144 < fVar3) {
              if (FLOAT_803df164 < fVar3) {
                if (FLOAT_803df168 < fVar3) {
                  if (FLOAT_803df16c < fVar3) {
                    if (FLOAT_803df170 < fVar3) {
                      if (FLOAT_803df174 < fVar3) {
                        dVar20 = (double)((fVar3 - FLOAT_803df174) / FLOAT_803df160);
                        iVar6 = 7;
                      }
                      else {
                        dVar20 = (double)((fVar3 - FLOAT_803df170) / FLOAT_803df160);
                        iVar6 = 6;
                      }
                    }
                    else {
                      dVar20 = (double)((fVar3 - FLOAT_803df16c) / FLOAT_803df160);
                      iVar6 = 5;
                    }
                  }
                  else {
                    dVar20 = (double)((fVar3 - FLOAT_803df168) / FLOAT_803df160);
                    iVar6 = 4;
                  }
                }
                else {
                  dVar20 = (double)((fVar3 - FLOAT_803df164) / FLOAT_803df160);
                  iVar6 = 3;
                }
              }
              else {
                dVar20 = (double)((fVar3 - FLOAT_803df144) / FLOAT_803df160);
                iVar6 = 2;
              }
            }
            else {
              dVar20 = (double)((fVar3 - FLOAT_803df160) / FLOAT_803df160);
              iVar6 = 1;
            }
          }
          else {
            dVar20 = (double)(fVar3 / FLOAT_803df160);
            iVar6 = 0;
          }
          dVar21 = (double)FUN_80010c64(dVar20,*piVar11 + iVar6 * 4 + 0x70,0);
          iVar1 = (iVar6 + 0xb) * 4;
          dVar19 = (double)FUN_80010c64(dVar20,*piVar11 + iVar1 + 0x70,0);
          dVar18 = (double)FUN_80010c64(dVar20,*piVar11 + (iVar6 + 0x16) * 4 + 0x70,0);
          dVar17 = (double)FUN_80010c64(dVar20,*piVar11 + iVar6 * 4 + 0x1fc,0);
          dVar20 = (double)FUN_80010c64(dVar20,*piVar11 + iVar1 + 0x1fc,0);
        }
      }
      else {
        dVar21 = (double)*(float *)(iVar6 + 0x70);
        dVar19 = (double)*(float *)(iVar6 + 0x9c);
        dVar18 = (double)*(float *)(iVar6 + 200);
        dVar17 = (double)*(float *)(iVar6 + 0x1fc);
        dVar20 = (double)*(float *)(iVar6 + 0x228);
      }
      dVar13 = (double)FLOAT_803df118;
      if ((dVar21 <= dVar13) && (dVar13 = dVar21, dVar21 < (double)FLOAT_803df108)) {
        dVar13 = (double)FLOAT_803df108;
      }
      dVar14 = (double)FLOAT_803df118;
      if ((dVar19 <= dVar14) && (dVar14 = dVar19, dVar19 < (double)FLOAT_803df108)) {
        dVar14 = (double)FLOAT_803df108;
      }
      dVar15 = (double)FLOAT_803df118;
      if ((dVar18 <= dVar15) && (dVar15 = dVar18, dVar18 < (double)FLOAT_803df108)) {
        dVar15 = (double)FLOAT_803df108;
      }
      iVar6 = *piVar11;
      if ((*(ushort *)(iVar6 + 6) & 0x40) != 0) {
        if (*(char *)(iVar6 + 0x314) == -1) {
          *(undefined *)(iVar6 + 0x314) = 1;
          *(float *)(*piVar11 + 0x6c) = FLOAT_803df108;
          iVar6 = (int)(-(float)(dVar20 - dVar17) * FLOAT_803df168);
          local_c8 = (double)(longlong)iVar6;
          iVar1 = (int)((float)(dVar20 - dVar17) * FLOAT_803df168);
          local_c0 = (double)(longlong)iVar1;
          uVar8 = FUN_800221a0(iVar6,iVar1);
          local_b8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
          *(float *)(*piVar11 + 0x68) = (float)(local_b8 - DOUBLE_803df130);
          uVar8 = FUN_800221a0(1,10);
          local_b0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
          *(float *)(*piVar11 + 100) = FLOAT_803df17c * (float)(local_b0 - DOUBLE_803df130);
        }
        else if (*(char *)(iVar6 + 0x314) == '\x01') {
          dVar17 = (double)(float)(dVar17 + (double)*(float *)(iVar6 + 0x6c));
          *(float *)(iVar6 + 0x6c) =
               (float)((double)*(float *)(iVar6 + 0x6c) + (double)*(float *)(iVar6 + 100));
          iVar6 = *piVar11;
          if (*(float *)(iVar6 + 0x68) < *(float *)(iVar6 + 0x6c)) {
            *(char *)(iVar6 + 0x314) = '\x01' - *(char *)(iVar6 + 0x314);
          }
        }
        else {
          dVar17 = (double)(float)(dVar17 + (double)*(float *)(iVar6 + 0x6c));
          *(float *)(iVar6 + 0x6c) =
               (float)((double)*(float *)(iVar6 + 0x6c) - (double)*(float *)(iVar6 + 100));
          fVar3 = FLOAT_803df108;
          iVar6 = *piVar11;
          if (*(float *)(iVar6 + 0x6c) < FLOAT_803df108) {
            *(char *)(iVar6 + 0x314) = '\x01' - *(char *)(iVar6 + 0x314);
            *(float *)(*piVar11 + 0x6c) = fVar3;
            local_b0 = (double)(longlong)(int)(dVar20 - dVar17);
            iVar6 = (int)(short)(int)(dVar20 - dVar17);
            uVar8 = FUN_800221a0(-iVar6 / 2,iVar6 / 2);
            local_b8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(*piVar11 + 0x68) = (float)(local_b8 - DOUBLE_803df130);
            uVar8 = FUN_800221a0(1,10);
            local_c0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(*piVar11 + 100) = FLOAT_803df17c * (float)(local_c0 - DOUBLE_803df130);
          }
        }
      }
      if ((double)FLOAT_803df180 < dVar20) {
        dVar20 = (double)FLOAT_803df180;
      }
      if (dVar20 < dVar17) {
        dVar17 = (double)(float)(dVar20 - (double)FLOAT_803df114);
      }
      if ((double)FLOAT_803df108 < dVar17) {
        FUN_8005cecc(0);
      }
      else {
        FUN_8005cecc(1);
      }
      iVar6 = *piVar11;
      uVar4 = *(ushort *)(iVar6 + 4);
      if ((uVar4 & 8) == 0) {
        local_b0 = (double)CONCAT44(0x43300000,
                                    (uint)local_106[0] + (uint)local_107 + (uint)local_108 ^
                                    0x80000000);
        dVar18 = (double)((float)(local_b0 - DOUBLE_803df130) / FLOAT_803df184);
        dVar13 = (double)(float)(dVar13 * dVar18);
        dVar14 = (double)(float)(dVar14 * dVar18);
        dVar15 = (double)(float)(dVar15 * dVar18);
      }
      if ((uVar4 & 1) == 0) {
        if ((uVar4 & 4) == 0) {
          iVar1 = (int)dVar13;
          local_b0 = (double)(longlong)iVar1;
          *(int *)(iVar6 + 0x24) = iVar1;
          iVar6 = (int)dVar14;
          local_b8 = (double)(longlong)iVar6;
          *(int *)(*piVar11 + 0x28) = iVar6;
          iVar2 = (int)dVar15;
          local_c0 = (double)(longlong)iVar2;
          *(int *)(*piVar11 + 0x2c) = iVar2;
          *(float *)(*piVar11 + 0x14) = (float)dVar17;
          *(float *)(*piVar11 + 0x18) = (float)dVar20;
          *(int *)(*piVar11 + 0x30) = iVar1;
          *(int *)(*piVar11 + 0x34) = iVar6;
          *(int *)(*piVar11 + 0x38) = iVar2;
          *(float *)(*piVar11 + 0x1c) = (float)dVar17;
          *(float *)(*piVar11 + 0x20) = (float)dVar20;
        }
        else {
          local_b0 = (double)(longlong)(int)dVar13;
          *(int *)(iVar6 + 0x30) = (int)dVar13;
          local_b8 = (double)(longlong)(int)dVar14;
          *(int *)(*piVar11 + 0x34) = (int)dVar14;
          local_c0 = (double)(longlong)(int)dVar15;
          *(int *)(*piVar11 + 0x38) = (int)dVar15;
          *(float *)(*piVar11 + 0x1c) = (float)dVar17;
          *(float *)(*piVar11 + 0x20) = (float)dVar20;
          if ((*(ushort *)(*piVar11 + 4) & 0x80) == 0) {
            *(undefined4 *)(*piVar11 + 0x24) = 0xff;
            *(undefined4 *)(*piVar11 + 0x28) = 0xff;
            *(undefined4 *)(*piVar11 + 0x2c) = 0xff;
            *(float *)(*piVar11 + 0x14) = FLOAT_803df188;
            *(float *)(*piVar11 + 0x18) = FLOAT_803df18c;
          }
        }
      }
      else {
        local_b0 = (double)(longlong)(int)dVar13;
        *(int *)(iVar6 + 0x24) = (int)dVar13;
        local_b8 = (double)(longlong)(int)dVar14;
        *(int *)(*piVar11 + 0x28) = (int)dVar14;
        local_c0 = (double)(longlong)(int)dVar15;
        *(int *)(*piVar11 + 0x2c) = (int)dVar15;
        *(float *)(*piVar11 + 0x14) = (float)dVar17;
        *(float *)(*piVar11 + 0x18) = (float)dVar20;
        if ((*(ushort *)(*piVar11 + 4) & 0x80) == 0) {
          *(undefined4 *)(*piVar11 + 0x30) = 0xff;
          *(undefined4 *)(*piVar11 + 0x34) = 0xff;
          *(undefined4 *)(*piVar11 + 0x38) = 0xff;
          *(float *)(*piVar11 + 0x1c) = FLOAT_803df188;
          *(float *)(*piVar11 + 0x20) = FLOAT_803df18c;
        }
      }
    }
    piVar11 = piVar11 + 1;
    iVar10 = iVar10 + 1;
  } while (iVar10 < 2);
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
  __psq_l0(auStack88,uVar12);
  __psq_l1(auStack88,uVar12);
  __psq_l0(auStack104,uVar12);
  __psq_l1(auStack104,uVar12);
  __psq_l0(auStack120,uVar12);
  __psq_l1(auStack120,uVar12);
  __psq_l0(auStack136,uVar12);
  __psq_l1(auStack136,uVar12);
  FUN_80286124();
  return;
}

