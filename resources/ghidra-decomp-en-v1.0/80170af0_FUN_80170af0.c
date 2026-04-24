// Function: FUN_80170af0
// Entry: 80170af0
// Size: 1148 bytes

/* WARNING: Removing unreachable block (ram,0x80170f44) */
/* WARNING: Removing unreachable block (ram,0x80170f34) */
/* WARNING: Removing unreachable block (ram,0x80170f24) */
/* WARNING: Removing unreachable block (ram,0x80170f2c) */
/* WARNING: Removing unreachable block (ram,0x80170f3c) */
/* WARNING: Removing unreachable block (ram,0x80170f4c) */

void FUN_80170af0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  byte bVar1;
  float fVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  uint uVar6;
  short *psVar7;
  int iVar8;
  char cVar10;
  int iVar9;
  int iVar11;
  int iVar12;
  byte bVar13;
  byte bVar14;
  uint uVar15;
  int iVar16;
  undefined4 uVar17;
  undefined8 in_f26;
  double dVar18;
  undefined8 in_f27;
  double dVar19;
  undefined8 in_f28;
  double dVar20;
  undefined8 in_f29;
  double dVar21;
  undefined8 in_f30;
  double dVar22;
  undefined8 in_f31;
  double dVar23;
  undefined8 uVar24;
  undefined auStack280 [8];
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  undefined4 local_100;
  uint uStack252;
  undefined4 local_f8;
  uint uStack244;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  longlong local_d8;
  double local_d0;
  undefined4 local_c8;
  uint uStack196;
  longlong local_c0;
  undefined4 local_b8;
  uint uStack180;
  double local_b0;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar17 = 0;
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
  uVar24 = FUN_802860b0();
  psVar7 = (short *)((ulonglong)uVar24 >> 0x20);
  iVar16 = *(int *)(psVar7 + 0x5c);
  if (param_6 != '\0') {
    iVar8 = FUN_8002b588();
    dVar23 = (double)*(float *)(psVar7 + 4);
    bVar1 = *(byte *)(psVar7 + 0x1b);
    uVar15 = (uint)bVar1;
    sVar3 = *psVar7;
    sVar4 = psVar7[1];
    sVar5 = psVar7[2];
    cVar10 = FUN_8002073c();
    fVar2 = FLOAT_803db414;
    if (cVar10 != '\0') {
      fVar2 = FLOAT_803e33ac;
    }
    dVar22 = (double)fVar2;
    if (psVar7[0x23] == 0x836) {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar6 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar6 + 0x5c) & 1) == 0) {
          iVar12 = uVar6 * 2;
          iVar11 = iVar16 + iVar12;
          *psVar7 = *(short *)(iVar11 + 0x44);
          psVar7[1] = *(short *)(iVar11 + 0x4c);
          psVar7[2] = *(short *)(iVar11 + 0x54);
          dVar18 = DOUBLE_803e33d0;
          uStack252 = (int)*(short *)(&DAT_803dbd78 + iVar12) ^ 0x80000000;
          local_100 = 0x43300000;
          uStack244 = (int)*(short *)(iVar11 + 0x44) ^ 0x80000000;
          local_f8 = 0x43300000;
          iVar9 = (int)(dVar22 * (double)(float)((double)CONCAT44(0x43300000,uStack252) -
                                                DOUBLE_803e33d0) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803e33d0));
          local_f0 = (longlong)iVar9;
          *(short *)(iVar11 + 0x44) = (short)iVar9;
          uStack228 = (int)*(short *)(&DAT_803dbd80 + iVar12) ^ 0x80000000;
          local_e8 = 0x43300000;
          uStack220 = (int)*(short *)(iVar11 + 0x4c) ^ 0x80000000;
          local_e0 = 0x43300000;
          iVar9 = (int)(dVar22 * (double)(float)((double)CONCAT44(0x43300000,uStack228) - dVar18) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack220) - dVar18));
          local_d8 = (longlong)iVar9;
          *(short *)(iVar11 + 0x4c) = (short)iVar9;
          local_d0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dbd88 + iVar12) ^ 0x80000000);
          uStack196 = (int)*(short *)(iVar11 + 0x54) ^ 0x80000000;
          local_c8 = 0x43300000;
          iVar9 = (int)(dVar22 * (double)(float)(local_d0 - dVar18) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack196) - dVar18));
          local_c0 = (longlong)iVar9;
          *(short *)(iVar11 + 0x54) = (short)iVar9;
          iVar9 = iVar16 + uVar6 * 4;
          *(float *)(psVar7 + 4) =
               (float)((double)*(float *)(iVar9 + 0x24) * dVar23) *
               (*(float *)(iVar16 + 4) / *(float *)(iVar16 + 0x10));
          local_b8 = 0x43300000;
          iVar9 = (int)(*(float *)(iVar9 + 0x14) *
                       (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e33e0));
          local_b0 = (double)(longlong)iVar9;
          *(char *)((int)psVar7 + 0x37) = (char)iVar9;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack180 = uVar15;
          FUN_8003b8f4((double)FLOAT_803e33c4,psVar7,(int)uVar24,param_3,param_4,param_5);
        }
      }
    }
    else {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar6 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar6 + 0x5c) & 1) == 0) {
          iVar12 = uVar6 * 2 + 0x44;
          *psVar7 = *(short *)(iVar16 + iVar12);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dbd70 + uVar6 * 2) ^ 0x80000000);
          uStack180 = (int)*(short *)(iVar16 + iVar12) ^ 0x80000000;
          local_b8 = 0x43300000;
          iVar9 = (int)(dVar22 * (double)(float)(local_b0 - DOUBLE_803e33d0) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e33d0));
          local_c0 = (longlong)iVar9;
          *(short *)(iVar16 + iVar12) = (short)iVar9;
          iVar9 = iVar16 + uVar6 * 4;
          *(float *)(psVar7 + 4) = (float)((double)*(float *)(iVar9 + 0x24) * dVar23);
          local_c8 = 0x43300000;
          iVar9 = (int)(*(float *)(iVar9 + 0x14) *
                       (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e33e0));
          local_d0 = (double)(longlong)iVar9;
          *(char *)((int)psVar7 + 0x37) = (char)iVar9;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack196 = uVar15;
          FUN_8003b8f4((double)FLOAT_803e33c4,psVar7,(int)uVar24,param_3,param_4,param_5);
          if (cVar10 == '\0') {
            dVar18 = (double)FLOAT_803e33d8;
            dVar19 = (double)FLOAT_803e33dc;
            dVar20 = (double)FLOAT_803e33ac;
            dVar21 = (double)FLOAT_803e33c4;
            for (bVar13 = 0; bVar13 < 2; bVar13 = bVar13 + 1) {
              local_10c = (float)(dVar18 * (double)*(float *)(psVar7 + 4));
              local_108 = (float)(dVar19 * (double)*(float *)(psVar7 + 4));
              local_104 = (float)dVar20;
              *psVar7 = *psVar7 + 0x7fff;
              FUN_80021ac8(psVar7,&local_10c);
              local_10c = local_10c + *(float *)(psVar7 + 6);
              local_108 = local_108 + *(float *)(psVar7 + 8);
              local_104 = local_104 + *(float *)(psVar7 + 10);
              local_110 = (float)dVar21;
              (**(code **)(*DAT_803dca88 + 8))(psVar7,0x7ec,auStack280,0x200001,0xffffffff,0);
            }
          }
        }
      }
    }
    *(float *)(psVar7 + 4) = (float)dVar23;
    *(byte *)(psVar7 + 0x1b) = bVar1;
    *psVar7 = sVar3;
    psVar7[1] = sVar4;
    psVar7[2] = sVar5;
  }
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  __psq_l0(auStack40,uVar17);
  __psq_l1(auStack40,uVar17);
  __psq_l0(auStack56,uVar17);
  __psq_l1(auStack56,uVar17);
  __psq_l0(auStack72,uVar17);
  __psq_l1(auStack72,uVar17);
  __psq_l0(auStack88,uVar17);
  __psq_l1(auStack88,uVar17);
  FUN_802860fc();
  return;
}

