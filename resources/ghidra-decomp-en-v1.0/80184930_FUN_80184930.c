// Function: FUN_80184930
// Entry: 80184930
// Size: 3476 bytes

/* WARNING: Removing unreachable block (ram,0x801856a4) */

void FUN_80184930(void)

{
  char cVar1;
  float fVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  short sVar12;
  float **ppfVar13;
  int iVar14;
  float *pfVar15;
  int iVar16;
  undefined4 uVar17;
  double dVar18;
  double dVar19;
  undefined8 in_f31;
  undefined4 local_170;
  undefined4 local_16c;
  undefined4 local_168;
  float local_164;
  int local_160;
  float **local_15c;
  float local_158 [2];
  float local_150;
  float local_14c;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  undefined auStack308 [24];
  short local_11c;
  undefined2 local_11a;
  undefined2 local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  undefined auStack260 [84];
  undefined auStack176 [64];
  float local_70 [4];
  undefined local_60;
  undefined local_5c;
  double local_40;
  double local_38;
  undefined auStack8 [8];
  
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar8 = (short *)FUN_802860d8();
  iVar16 = 0;
  local_15c = (float **)0x0;
  local_140 = DAT_802c2298;
  local_13c = DAT_802c229c;
  local_138 = DAT_802c22a0;
  local_14c = DAT_802c22a4;
  local_148 = DAT_802c22a8;
  local_144 = DAT_802c22ac;
  bVar3 = false;
  pfVar15 = *(float **)(psVar8 + 0x5c);
  iVar9 = FUN_8002b9ec();
  if ((*(byte *)(pfVar15 + 10) & 1) != 0) {
    while (iVar10 = FUN_800374ec(psVar8,&local_160,0,0), iVar10 != 0) {
      if (local_160 == 0x7000b) {
        local_168 = DAT_803e39f0;
        FUN_802968ac(iVar9,*(undefined *)((int)&local_168 + (uint)*(byte *)((int)pfVar15 + 0x27)));
        *(undefined2 *)(pfVar15 + 4) = 0x50;
        *(undefined2 *)(pfVar15 + 5) = 0;
        *(byte *)(pfVar15 + 10) = *(byte *)(pfVar15 + 10) & 0xfe;
      }
    }
    if ((*(byte *)(pfVar15 + 10) & 1) != 0) goto LAB_801856a4;
  }
  FUN_8000d8e4(psVar8,0x406,3);
  fVar2 = FLOAT_803e3a20;
  sVar12 = *(short *)(pfVar15 + 5);
  if (sVar12 == 0) {
    *(ushort *)(pfVar15 + 4) = *(short *)(pfVar15 + 4) - (ushort)DAT_803db410;
    if (*(short *)(pfVar15 + 4) < 1) {
      *(undefined2 *)(pfVar15 + 4) = 0;
      FUN_8002cbc4(psVar8);
    }
  }
  else {
    cVar1 = *(char *)(pfVar15 + 9);
    if (cVar1 == '\0') {
      if (*(int *)(psVar8 + 0x2a) != 0) {
        FUN_80035f20(psVar8);
      }
      *(float *)(psVar8 + 6) = *(float *)(psVar8 + 0x12) * FLOAT_803db414 + *(float *)(psVar8 + 6);
      *(float *)(psVar8 + 8) = *(float *)(psVar8 + 0x14) * FLOAT_803db414 + *(float *)(psVar8 + 8);
      *(float *)(psVar8 + 10) = *(float *)(psVar8 + 0x16) * FLOAT_803db414 + *(float *)(psVar8 + 10)
      ;
      if (FLOAT_803e3a08 < *(float *)(psVar8 + 0x14)) {
        *(float *)(psVar8 + 0x14) = FLOAT_803e3a0c * FLOAT_803db414 + *(float *)(psVar8 + 0x14);
      }
      psVar8[2] = psVar8[2] + *(short *)((int)pfVar15 + 0x16) * (ushort)DAT_803db410;
      iVar16 = FUN_801843c0(psVar8);
      uVar11 = (uint)(iVar16 != 0);
      if (uVar11 == 0) {
        uVar11 = FUN_800640cc((double)FLOAT_803e3a00,psVar8 + 0x40,psVar8 + 6,0,auStack260,psVar8,8,
                              0xffffffff,0,0);
      }
      if (uVar11 != 0) {
        psVar8[2] = 0;
        *(undefined *)(pfVar15 + 9) = 1;
        *(short *)(pfVar15 + 6) = *psVar8;
        fVar7 = FLOAT_803e3a1c;
        fVar6 = FLOAT_803e3a18;
        fVar5 = FLOAT_803e3a14;
        fVar4 = FLOAT_803e3a10;
        fVar2 = FLOAT_803e39f8;
        sVar12 = psVar8[0x23];
        if (sVar12 == 0x3d3) {
          *pfVar15 = FLOAT_803e3a10 * *(float *)(psVar8 + 0x12);
          pfVar15[1] = fVar4 * *(float *)(psVar8 + 0x16);
        }
        else if (sVar12 == 0x3d4) {
          *pfVar15 = FLOAT_803e3a14 * *(float *)(psVar8 + 0x12);
          pfVar15[1] = fVar5 * *(float *)(psVar8 + 0x16);
        }
        else if (sVar12 == 0x3d5) {
          *pfVar15 = FLOAT_803e3a18 * *(float *)(psVar8 + 0x12);
          pfVar15[1] = fVar6 * *(float *)(psVar8 + 0x16);
        }
        else if (sVar12 == 0x3d6) {
          *pfVar15 = FLOAT_803e3a1c * *(float *)(psVar8 + 0x12);
          pfVar15[1] = fVar7 * *(float *)(psVar8 + 0x16);
        }
        else if (sVar12 == 0x3df) {
          *pfVar15 = FLOAT_803e39f8;
          pfVar15[1] = fVar2;
        }
      }
    }
    else if ((cVar1 == '\x02') && (sVar12 != 0)) {
      local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar15 + 7) ^ 0x80000000);
      if (pfVar15[2] < (float)(local_40 - DOUBLE_803e3a48)) {
        pfVar15[2] = FLOAT_803e3a20 * FLOAT_803db414 + pfVar15[2];
        local_140 = *(float *)(psVar8 + 6);
        local_14c = fVar2 * *(float *)(psVar8 + 0x12) * FLOAT_803db414 + local_140;
        local_13c = *(float *)(psVar8 + 8);
        local_148 = fVar2 * FLOAT_803db414 + local_13c;
        local_138 = *(float *)(psVar8 + 10);
        local_144 = fVar2 * *(float *)(psVar8 + 0x16) * FLOAT_803db414 + local_138;
        local_70[0] = FLOAT_803e39f8;
        local_60 = 0xff;
        local_5c = 0;
        FUN_8006961c(auStack308,&local_140,&local_14c,local_70,1);
        FUN_800691c0(psVar8,auStack308,0,1);
        iVar16 = FUN_80067958(psVar8,&local_140,&local_14c,1,auStack176,0);
        *(float *)(psVar8 + 6) = local_14c;
        *(float *)(psVar8 + 8) = local_148;
        *(float *)(psVar8 + 10) = local_144;
        if (iVar16 != 0) {
          FUN_801845fc(psVar8,0,0,auStack176);
        }
      }
      iVar16 = FUN_8003687c(psVar8,0,0,0);
      if (iVar16 == 0xe) {
        *(undefined2 *)((int)pfVar15 + 0x1a) = 0xfa;
        FUN_8000bb18(psVar8,0x40);
        *(float *)(psVar8 + 0x12) = *(float *)(iVar9 + 0xc) - *(float *)(psVar8 + 6);
        *(float *)(psVar8 + 0x16) = *(float *)(iVar9 + 0x14) - *(float *)(psVar8 + 10);
        *psVar8 = 0;
        dVar19 = (double)(*(float *)(psVar8 + 0x12) * *(float *)(psVar8 + 0x12) +
                         *(float *)(psVar8 + 0x16) * *(float *)(psVar8 + 0x16));
        if (dVar19 != (double)FLOAT_803e39f8) {
          dVar19 = (double)FUN_802931a0();
        }
        dVar18 = (double)FLOAT_803e39fc;
        *(float *)(psVar8 + 0x12) = *(float *)(psVar8 + 0x12) / (float)(dVar18 * dVar19);
        *(float *)(psVar8 + 0x16) = *(float *)(psVar8 + 0x16) / (float)(dVar18 * dVar19);
        psVar8[1] = 0;
        *(float *)(psVar8 + 0x14) = FLOAT_803e3a24;
        local_110 = FLOAT_803e39f8;
        local_10c = FLOAT_803e39f8;
        local_108 = FLOAT_803e39f8;
        local_114 = FLOAT_803e3a00;
        local_118 = 0;
        local_11a = 0;
        local_11c = FUN_800221a0(0xffffd8f0,10000);
        FUN_80021ac8(&local_11c,psVar8 + 0x12);
        uVar11 = FUN_800217c0((double)*(float *)(psVar8 + 0x12),-(double)*(float *)(psVar8 + 0x16));
        iVar16 = (int)*psVar8 - (uVar11 & 0xffff);
        if (0x8000 < iVar16) {
          iVar16 = iVar16 + -0xffff;
        }
        if (iVar16 < -0x8000) {
          iVar16 = iVar16 + 0xffff;
        }
        *psVar8 = (short)iVar16;
        *(undefined *)(pfVar15 + 9) = 0;
        pfVar15[2] = FLOAT_803e39f8;
        fVar2 = FLOAT_803e39f4;
        *(float *)(psVar8 + 6) =
             FLOAT_803e39f4 * *(float *)(psVar8 + 0x12) * FLOAT_803db414 + *(float *)(psVar8 + 6);
        *(float *)(psVar8 + 8) =
             fVar2 * *(float *)(psVar8 + 0x14) * FLOAT_803db414 + *(float *)(psVar8 + 8);
        *(float *)(psVar8 + 10) =
             fVar2 * *(float *)(psVar8 + 0x16) * FLOAT_803db414 + *(float *)(psVar8 + 10);
      }
    }
    else if ((cVar1 == '\x01') && (sVar12 != 0)) {
      if (*(short *)((int)pfVar15 + 0x1a) == 0) {
        iVar16 = 0;
        dVar19 = (double)FLOAT_803e3a28;
        iVar10 = FUN_80065e50((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                              (double)*(float *)(psVar8 + 10),psVar8,&local_15c,1,0);
        iVar14 = 0;
        ppfVar13 = local_15c;
        if (0 < iVar10) {
          do {
            dVar18 = (double)(**ppfVar13 - *(float *)(psVar8 + 8));
            if (dVar18 <= (double)FLOAT_803dbdc8) {
              if (dVar18 < (double)FLOAT_803e39f8) {
                dVar18 = -dVar18;
              }
              if (dVar18 < dVar19) {
                iVar16 = iVar14;
                dVar19 = dVar18;
              }
            }
            ppfVar13 = ppfVar13 + 1;
            iVar14 = iVar14 + 1;
            iVar10 = iVar10 + -1;
          } while (iVar10 != 0);
        }
        if (local_15c == (float **)0x0) {
          *(float *)(psVar8 + 8) = pfVar15[3];
        }
        else {
          *(float *)(psVar8 + 8) = *local_15c[iVar16];
          fVar2 = local_15c[iVar16][2];
          if (fVar2 < FLOAT_803e39f8) {
            fVar2 = -fVar2;
          }
          if (FLOAT_803dbdc4 <= fVar2) {
            FUN_801845fc(psVar8,local_15c[iVar16],1,auStack176);
          }
          else {
            bVar3 = true;
          }
        }
        if (psVar8[0x23] != 0x3d6) {
          sVar12 = FUN_800221a0(0xfffffa4c,0x5b4);
          *psVar8 = *psVar8 + sVar12;
        }
        *(float *)(psVar8 + 0x12) = *pfVar15;
        local_110 = FLOAT_803e39f8;
        *(float *)(psVar8 + 0x14) = FLOAT_803e39f8;
        *(float *)(psVar8 + 0x16) = pfVar15[1];
        local_10c = local_110;
        local_108 = local_110;
        local_114 = FLOAT_803e3a00;
        local_118 = 0;
        local_11a = 0;
        local_11c = *psVar8 - *(short *)(pfVar15 + 6);
        FUN_80021ac8(&local_11c,psVar8 + 0x12);
        *(ushort *)(pfVar15 + 5) = *(short *)(pfVar15 + 5) - (ushort)DAT_803db410;
        if (*(short *)(pfVar15 + 5) < 1) {
          iVar10 = FUN_8005a10c((double)(*(float *)(psVar8 + 0x54) * *(float *)(psVar8 + 4)),
                                psVar8 + 6);
          if (iVar10 == 0) {
            *(undefined2 *)(pfVar15 + 5) = 0;
          }
          else {
            *(undefined2 *)(pfVar15 + 5) = 1;
          }
        }
        if (bVar3) {
          uVar11 = FUN_800217c0((double)local_15c[iVar16][1],(double)local_15c[iVar16][3]);
          local_40 = (double)CONCAT44(0x43300000,uVar11 & 0xffff);
          iVar10 = (int)(FLOAT_803dbdcc * (float)(local_40 - DOUBLE_803e3a50) + FLOAT_803e3a2c);
          local_38 = (double)(longlong)iVar10;
          *psVar8 = (short)iVar10;
          fVar2 = FLOAT_803e39f4;
          *(float *)(psVar8 + 6) =
               FLOAT_803db414 * FLOAT_803e39f4 * local_15c[iVar16][1] + *(float *)(psVar8 + 6);
          *(float *)(psVar8 + 10) =
               FLOAT_803db414 * fVar2 * local_15c[iVar16][3] + *(float *)(psVar8 + 10);
          *(float *)(psVar8 + 0x12) = local_15c[iVar16][1];
          *(float *)(psVar8 + 0x16) = local_15c[iVar16][3];
        }
        else {
          *(float *)(psVar8 + 6) =
               *(float *)(psVar8 + 0x12) * FLOAT_803db414 + *(float *)(psVar8 + 6);
          *(float *)(psVar8 + 10) =
               *(float *)(psVar8 + 0x16) * FLOAT_803db414 + *(float *)(psVar8 + 10);
          FUN_802931a0((double)(*(float *)(psVar8 + 0x12) * *(float *)(psVar8 + 0x12) +
                               *(float *)(psVar8 + 0x16) * *(float *)(psVar8 + 0x16)));
          FUN_8002f5d4(psVar8,&local_164);
          FUN_8002fa48((double)local_164,(double)FLOAT_803db414,psVar8,0);
        }
        iVar16 = FUN_800640cc((double)FLOAT_803e3a00,psVar8 + 0x40,psVar8 + 6,0,auStack260,psVar8,8,
                              0xffffffff,0,0);
        local_70[0] = FLOAT_803e3a00;
        local_60 = 0xff;
        local_5c = 10;
        FUN_8006961c(auStack308,psVar8 + 0x40,psVar8 + 6,local_70,1);
        FUN_800691c0(psVar8,auStack308,0,1);
        uVar11 = FUN_80067958(psVar8,psVar8 + 0x40,psVar8 + 6,1,auStack176,0);
        if (((iVar16 != 0) ||
            (dVar19 = (double)FUN_80021704(psVar8 + 0xc,*(int *)(psVar8 + 0x26) + 8),
            (double)FLOAT_803e3a30 < dVar19)) || (((uVar11 & 1) != 0 && ((uVar11 & 0x10) == 0)))) {
          FUN_80247754(*(int *)(psVar8 + 0x26) + 8,psVar8 + 6,local_158);
          uVar11 = FUN_800217c0((double)local_158[0],(double)local_150);
          local_38 = (double)CONCAT44(0x43300000,uVar11 & 0xffff);
          iVar16 = (int)(FLOAT_803dbdd0 * (float)(local_38 - DOUBLE_803e3a50) + FLOAT_803e3a2c);
          local_40 = (double)(longlong)iVar16;
          *psVar8 = (short)iVar16;
        }
      }
      else {
        dVar19 = (double)FLOAT_803e3a28;
        iVar10 = FUN_80065e50((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                              (double)*(float *)(psVar8 + 10),psVar8,&local_15c,1,0);
        iVar14 = 0;
        ppfVar13 = local_15c;
        if (0 < iVar10) {
          do {
            dVar18 = (double)(**ppfVar13 - *(float *)(psVar8 + 8));
            if (dVar18 < (double)FLOAT_803e39f8) {
              dVar18 = (double)(float)(dVar18 * (double)FLOAT_803e3a34);
            }
            if (dVar18 < dVar19) {
              iVar16 = iVar14;
              dVar19 = dVar18;
            }
            ppfVar13 = ppfVar13 + 1;
            iVar14 = iVar14 + 1;
            iVar10 = iVar10 + -1;
          } while (iVar10 != 0);
        }
        if (local_15c == (float **)0x0) {
          *(float *)(psVar8 + 8) = pfVar15[3];
        }
        else {
          *(float *)(psVar8 + 8) = *local_15c[iVar16];
          FUN_801845fc(psVar8,local_15c[iVar16],1,auStack176);
        }
        *(ushort *)((int)pfVar15 + 0x1a) = *(short *)((int)pfVar15 + 0x1a) - (ushort)DAT_803db410;
        if (*(short *)((int)pfVar15 + 0x1a) < 1) {
          *(undefined2 *)((int)pfVar15 + 0x1a) = 0;
        }
      }
      if (((*(short *)((int)pfVar15 + 0x1a) != 0) || (psVar8[0x23] != 0x3d6)) &&
         (dVar19 = (double)FUN_80021690(iVar9 + 0x18,psVar8 + 0xc), dVar19 < (double)FLOAT_803e3a38)
         ) {
        fVar2 = *(float *)(psVar8 + 8) - *(float *)(iVar9 + 0x10);
        if (fVar2 < FLOAT_803e39f8) {
          fVar2 = -fVar2;
        }
        if (fVar2 < FLOAT_803e3a3c) {
          iVar16 = FUN_8001ffb4(0x910);
          if (iVar16 == 0) {
            *(undefined2 *)(pfVar15 + 0xb) = 0xffff;
            *(undefined2 *)((int)pfVar15 + 0x2e) = 0;
            pfVar15[0xc] = FLOAT_803e3a00;
            FUN_800378c4(iVar9,0x7000a,psVar8,pfVar15 + 0xb);
            FUN_800200e8(0x910,1);
            *(byte *)(pfVar15 + 10) = *(byte *)(pfVar15 + 10) | 1;
          }
          else {
            local_16c = DAT_803e39f0;
            FUN_802968ac(iVar9,*(undefined *)
                                ((int)&local_16c + (uint)*(byte *)((int)pfVar15 + 0x27)));
            *(undefined2 *)(pfVar15 + 4) = 0x50;
            *(undefined2 *)(pfVar15 + 5) = 0;
          }
          if (*(int *)(psVar8 + 0x2a) != 0) {
            FUN_80035f00(psVar8);
          }
          FUN_8000bb18(psVar8,*(undefined2 *)((int)pfVar15 + 0x1e));
          FUN_800999b4((double)FLOAT_803e3a00,psVar8,(int)*(short *)(pfVar15 + 8),0x28);
        }
      }
      if ((*(short *)((int)pfVar15 + 0x1a) == 0) && (psVar8[0x23] == 0x3d6)) {
        dVar19 = (double)FUN_80021690(iVar9 + 0x18,psVar8 + 0xc);
        if (dVar19 < (double)FLOAT_803e3a3c) {
          fVar2 = *(float *)(psVar8 + 8) - *(float *)(iVar9 + 0x10);
          if (fVar2 < FLOAT_803e39f8) {
            fVar2 = -fVar2;
          }
          if (fVar2 < FLOAT_803e3a3c) {
            iVar16 = FUN_8001ffb4(0x1d9);
            if (iVar16 == 0) {
              FUN_800378c4(iVar9,0x60004,psVar8,1);
            }
            fVar2 = FLOAT_803e3a40;
            *(float *)(psVar8 + 6) =
                 FLOAT_803e3a40 * -*(float *)(psVar8 + 0x12) + *(float *)(psVar8 + 6);
            *(float *)(psVar8 + 10) = fVar2 * -*(float *)(psVar8 + 0x16) + *(float *)(psVar8 + 10);
            FUN_8000bb18(psVar8,0x45);
          }
        }
        iVar16 = FUN_8003687c(psVar8,0,0,0);
        if (iVar16 == 0xe) {
          *(undefined2 *)((int)pfVar15 + 0x1a) = 0xfa;
          FUN_8000bb18(psVar8,0x40);
        }
      }
      else if ((*(short *)((int)pfVar15 + 0x1a) != 0) &&
              ((psVar8[0x23] == 0x3d6 && (iVar16 = FUN_8003687c(psVar8,0,0,0), iVar16 == 0xe)))) {
        FUN_8000bb18(psVar8,0x46);
        local_170 = DAT_803e39f0;
        FUN_802968ac(iVar9,*(undefined *)((int)&local_170 + (uint)*(byte *)((int)pfVar15 + 0x27)));
        *(undefined2 *)(pfVar15 + 4) = 0x50;
        *(undefined2 *)(pfVar15 + 5) = 0;
      }
    }
  }
LAB_801856a4:
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  FUN_80286124();
  return;
}

