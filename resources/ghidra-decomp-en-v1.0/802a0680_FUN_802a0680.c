// Function: FUN_802a0680
// Entry: 802a0680
// Size: 2708 bytes

/* WARNING: Removing unreachable block (ram,0x802a10ec) */
/* WARNING: Removing unreachable block (ram,0x802a10dc) */
/* WARNING: Removing unreachable block (ram,0x802a10e4) */
/* WARNING: Removing unreachable block (ram,0x802a10f4) */

void FUN_802a0680(void)

{
  double dVar1;
  double dVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  bool bVar9;
  uint uVar10;
  int iVar11;
  undefined2 uVar13;
  uint uVar12;
  uint *puVar14;
  int iVar15;
  short sVar16;
  int iVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined8 in_f28;
  double dVar20;
  double dVar21;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar22;
  double in_f31;
  undefined8 uVar23;
  undefined auStack240 [8];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  undefined auStack196 [12];
  float local_b8;
  float local_b4;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  float local_88;
  float local_84;
  float local_7c;
  byte local_72;
  longlong local_70;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar19 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar23 = FUN_802860cc();
  iVar11 = (int)((ulonglong)uVar23 >> 0x20);
  puVar14 = (uint *)uVar23;
  iVar17 = *(int *)(iVar11 + 0xb8);
  if (*(char *)((int)puVar14 + 0x27a) != '\0') {
    DAT_803dc6a0 = 0x10;
    FUN_80035e8c();
  }
  iVar15 = *(int *)(iVar11 + 0xb8);
  *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) & 0xfffffffd;
  *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x2000;
  puVar14[1] = puVar14[1] | 0x100000;
  fVar3 = FLOAT_803e7ea4;
  puVar14[0xa0] = (uint)FLOAT_803e7ea4;
  puVar14[0xa1] = (uint)fVar3;
  *puVar14 = *puVar14 | 0x200000;
  *(float *)(iVar11 + 0x24) = fVar3;
  *(float *)(iVar11 + 0x2c) = fVar3;
  puVar14[1] = puVar14[1] | 0x8000000;
  *(float *)(iVar11 + 0x28) = fVar3;
  uVar18 = *(undefined4 *)(*(int *)(iVar11 + 0x7c) + *(char *)(iVar11 + 0xad) * 4);
  dVar20 = (double)(float)puVar14[0xa8];
  DAT_803dc6a2 = DAT_803dc6a0;
  if ((short)DAT_803dc6a0 < 0x15) {
    if (DAT_803dc6a0 != 0x10) goto LAB_802a07f0;
    if (*(short *)(iVar11 + 0xa0) == 0x66) {
      *(undefined2 *)(iVar17 + 0x5a6) = 0;
      DAT_803dc6a0 = 0x16;
    }
    else {
      *(undefined2 *)(iVar17 + 0x5a6) = 1;
      DAT_803dc6a0 = 0x15;
    }
    *(undefined4 *)(iVar11 + 0x10) = *(undefined4 *)(iVar17 + 0x76c);
    dVar20 = (double)FLOAT_803e7ff8;
LAB_802a07b4:
    fVar3 = FLOAT_803e7ea4;
    *(float *)(iVar17 + 0x564) = FLOAT_803e7ea4;
    *(float *)(iVar17 + 0x560) = fVar3;
    *(float *)(iVar17 + 0x568) = fVar3;
    FUN_802a13f4(iVar11,puVar14);
    if (FLOAT_803e7efc < (float)puVar14[0xa6]) {
      in_f31 = (double)*(float *)(iVar11 + 0x98);
      *(float *)(iVar11 + 0x98) = FLOAT_803e7ee0;
      goto LAB_802a07f0;
    }
  }
  else {
    if ((short)DAT_803dc6a0 < 0x17) goto LAB_802a07b4;
LAB_802a07f0:
    if (FLOAT_803e7ee0 == *(float *)(iVar11 + 0x98)) {
      local_dc = -(FLOAT_803e7f30 * *(float *)(iVar17 + 0x56c) - *(float *)(iVar17 + 0x768));
      local_d8 = *(float *)(iVar17 + 0x76c);
      local_d4 = -(FLOAT_803e7f30 * *(float *)(iVar17 + 0x574) - *(float *)(iVar17 + 0x770));
      iVar15 = FUN_800640cc((double)FLOAT_803e7ea4,iVar17 + 0x768,&local_dc,3,auStack196,iVar11,1,3,
                            0xff,0);
      if (iVar15 == 0) {
        iVar15 = 2;
      }
      else {
        *(float *)(iVar11 + 0xc) = local_dc;
        *(float *)(iVar11 + 0x14) = local_d4;
        *(float *)(iVar17 + 0x54c) = local_7c * (local_84 - local_88) + local_88;
        *(float *)(iVar17 + 0x550) = local_7c * (local_b4 - local_b8) + local_b8;
        *(undefined4 *)(iVar17 + 0x56c) = local_a8;
        *(undefined4 *)(iVar17 + 0x570) = local_a4;
        *(float *)(iVar17 + 0x574) = local_a0;
        *(undefined4 *)(iVar17 + 0x578) = local_9c;
        *(float *)(iVar17 + 0x57c) = -local_a0;
        *(float *)(iVar17 + 0x580) = FLOAT_803e7ea4;
        *(undefined4 *)(iVar17 + 0x584) = local_a8;
        *(float *)(iVar17 + 0x588) =
             -(local_d4 * *(float *)(iVar17 + 0x584) +
              local_dc * *(float *)(iVar17 + 0x57c) + local_d8 * *(float *)(iVar17 + 0x580));
        uVar13 = FUN_800217c0((double)*(float *)(iVar17 + 0x56c),(double)*(float *)(iVar17 + 0x574))
        ;
        *(undefined2 *)(iVar17 + 0x478) = uVar13;
        *(undefined2 *)(iVar17 + 0x484) = *(undefined2 *)(iVar17 + 0x478);
        if ((local_72 & 4) == 0) {
          if ((local_72 & 8) == 0) {
            if ((local_72 & 2) == 0) {
              iVar15 = 3;
            }
            else {
              iVar15 = 2;
            }
          }
          else {
            iVar15 = 1;
          }
        }
        else {
          iVar15 = 0;
        }
      }
      if ((DAT_803dc6a0 != 0x15) && (DAT_803dc6a0 != 0x16)) {
        *(undefined4 *)(iVar11 + 0x10) = *(undefined4 *)(iVar17 + 0x76c);
      }
      if ((float)puVar14[0xa6] <= FLOAT_803e7efc) {
        *(undefined4 *)(iVar11 + 0x10) = *(undefined4 *)(iVar17 + 0x76c);
        if (*(short *)(iVar17 + 0x5a6) == 0) {
          DAT_803dc6a0 = 0x16;
        }
        else {
          DAT_803dc6a0 = 0x15;
        }
        dVar20 = (double)FLOAT_803e7ff8;
      }
      else {
        uVar12 = FUN_800217c0((double)(float)puVar14[0xa4],-(double)(float)puVar14[0xa3]);
        uVar12 = (uVar12 & 0xffff) + 0x1000 >> 0xd;
        DAT_803dc6a0 = (ushort)uVar12 & 7;
        DAT_803dc6a2 = 0xffff;
        if ((DAT_803dc6a0 == 4) || ((uVar12 & 7) == 0)) {
          *(ushort *)(iVar17 + 0x5a6) = *(ushort *)(iVar17 + 0x5a6) ^ 1;
        }
        bVar6 = false;
        bVar7 = false;
        bVar8 = false;
        bVar9 = false;
        switch(DAT_803dc6a0) {
        case 0:
          bVar7 = true;
          break;
        case 1:
          bVar7 = true;
          bVar9 = true;
          break;
        case 2:
          bVar9 = true;
          break;
        case 3:
          bVar6 = true;
          bVar9 = true;
          break;
        case 4:
          bVar6 = true;
          break;
        case 5:
          bVar6 = true;
          bVar8 = true;
          break;
        case 6:
          bVar8 = true;
          break;
        case 7:
          bVar7 = true;
          bVar8 = true;
        }
        if (*(short *)(iVar17 + 0x5a6) != 0) {
          DAT_803dc6a0 = DAT_803dc6a0 + 8;
        }
        if (bVar6) {
          fVar3 = *(float *)(iVar17 + 0x54c) - *(float *)(iVar17 + 0x76c);
          fVar4 = DAT_803dafb8;
          if (DAT_803dafb8 < FLOAT_803e7ea4) {
            fVar4 = -DAT_803dafb8;
          }
          fVar5 = DAT_803dafbc;
          if (DAT_803dafbc < FLOAT_803e7ea4) {
            fVar5 = -DAT_803dafbc;
          }
          if ((fVar3 < fVar5) && ((iVar15 == 0 || (iVar15 == 3)))) {
            fVar3 = (fVar3 - fVar4) / (fVar5 - fVar4);
            fVar4 = FLOAT_803e7ea4;
            if ((FLOAT_803e7ea4 <= fVar3) && (fVar4 = fVar3, FLOAT_803e7ee0 < fVar3)) {
              fVar4 = FLOAT_803e7ee0;
            }
            local_70 = (longlong)(int)(FLOAT_803e7fac * fVar4);
            *(short *)(iVar17 + 0x5a4) = (short)(int)(FLOAT_803e7fac * fVar4);
            *(float *)(iVar17 + 0x560) = fVar4;
            puVar14[0xc2] = (uint)FUN_8029ffd0;
            uVar18 = 0x15;
            goto LAB_802a10dc;
          }
        }
        else if (bVar7) {
          fVar3 = *(float *)(iVar17 + 0x76c) - *(float *)(iVar17 + 0x550);
          fVar4 = DAT_803dafc0;
          if (DAT_803dafc0 < FLOAT_803e7ea4) {
            fVar4 = -DAT_803dafc0;
          }
          fVar5 = DAT_803dafc4;
          if (DAT_803dafc4 < FLOAT_803e7ea4) {
            fVar5 = -DAT_803dafc4;
          }
          if ((fVar3 < fVar5) && ((iVar15 == 1 || (iVar15 == 3)))) {
            fVar3 = (fVar3 - fVar4) / (fVar5 - fVar4);
            fVar4 = FLOAT_803e7ea4;
            if ((FLOAT_803e7ea4 <= fVar3) && (fVar4 = fVar3, FLOAT_803e7ee0 < fVar3)) {
              fVar4 = FLOAT_803e7ee0;
            }
            local_70 = (longlong)(int)(FLOAT_803e7fac * fVar4);
            *(short *)(iVar17 + 0x5a4) = (short)(int)(FLOAT_803e7fac * fVar4);
            *(float *)(iVar17 + 0x560) = fVar4;
            puVar14[0xc2] = (uint)FUN_8029ffd0;
            uVar18 = 0x16;
            goto LAB_802a10dc;
          }
        }
        FUN_8002f23c((double)FLOAT_803e7ea4,iVar11,
                     (int)*(short *)(&DAT_80332f48 + (short)DAT_803dc6a0 * 2),1);
        FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(iVar11 + 8),uVar18,1,0,&local_d0,
                     auStack240);
        *(undefined2 *)(iVar11 + 0xa2) = 0xffff;
        *(float *)(iVar17 + 0x564) = *(float *)(iVar17 + 0x57c) * -local_d0;
        *(float *)(iVar17 + 0x560) = local_cc;
        *(float *)(iVar17 + 0x568) = *(float *)(iVar17 + 0x584) * -local_d0;
        if ((!bVar6) && (!bVar7)) {
          *(float *)(iVar17 + 0x560) = FLOAT_803e7ea4;
        }
        fVar3 = FLOAT_803e7ea4;
        if ((!bVar8) && (!bVar9)) {
          *(float *)(iVar17 + 0x564) = FLOAT_803e7ea4;
          *(float *)(iVar17 + 0x568) = fVar3;
        }
        uVar12 = 0;
        if (FLOAT_803e7ea4 <= local_d0) {
          fVar3 = -*(float *)(iVar17 + 0x57c);
          fVar4 = -*(float *)(iVar17 + 0x584);
        }
        else {
          fVar3 = *(float *)(iVar17 + 0x57c);
          fVar4 = *(float *)(iVar17 + 0x584);
        }
        dVar22 = (double)(FLOAT_803e7ffc * fVar3);
        dVar20 = (double)(FLOAT_803e7ffc * fVar4);
        if ((bVar6) || (bVar7)) {
          local_d8 = *(float *)(iVar17 + 0x76c) + local_cc;
          if (FLOAT_803e7ea4 <= local_cc) {
            local_d8 = local_d8 + FLOAT_803e7f50;
          }
          else {
            local_d8 = local_d8 - FLOAT_803e7f50;
          }
          dVar21 = (double)FLOAT_803e7f30;
          for (sVar16 = 0; sVar16 < 2; sVar16 = sVar16 + 1) {
            if (sVar16 == 0) {
              dVar1 = (double)*(float *)(iVar17 + 0x768) - dVar22;
              dVar2 = (double)*(float *)(iVar17 + 0x770) - dVar20;
            }
            else {
              dVar1 = (double)*(float *)(iVar17 + 0x768) + dVar22;
              dVar2 = (double)*(float *)(iVar17 + 0x770) + dVar20;
            }
            local_d4 = (float)dVar2;
            local_dc = (float)dVar1;
            local_e8 = -(float)(dVar21 * (double)*(float *)(iVar17 + 0x56c) - (double)local_dc);
            local_e4 = local_d8;
            local_e0 = -(float)(dVar21 * (double)*(float *)(iVar17 + 0x574) - (double)local_d4);
            iVar15 = FUN_800640cc((double)FLOAT_803e7ea4,&local_dc,&local_e8,3,0,iVar11,1,3,0xff,0);
            if (iVar15 != 0) {
              uVar12 = uVar12 | 1 << (int)sVar16;
            }
          }
        }
        else {
          uVar12 = 3;
        }
        if ((bVar8) || (bVar9)) {
          local_dc = (float)(dVar22 + (double)(*(float *)(iVar17 + 0x768) +
                                              *(float *)(iVar17 + 0x564)));
          local_d4 = (float)(dVar20 + (double)(*(float *)(iVar17 + 0x770) +
                                              *(float *)(iVar17 + 0x568)));
          dVar20 = (double)FLOAT_803e7f30;
          for (sVar16 = 0; sVar16 < 2; sVar16 = sVar16 + 1) {
            if (sVar16 == 0) {
              local_d8 = *(float *)(iVar17 + 0x76c) - FLOAT_803e7f50;
            }
            else {
              local_d8 = FLOAT_803e7f50 + *(float *)(iVar17 + 0x76c);
            }
            local_e8 = -(float)(dVar20 * (double)*(float *)(iVar17 + 0x56c) - (double)local_dc);
            local_e4 = local_d8;
            local_e0 = -(float)(dVar20 * (double)*(float *)(iVar17 + 0x574) - (double)local_d4);
            iVar15 = FUN_800640cc((double)FLOAT_803e7ea4,&local_dc,&local_e8,3,0,iVar11,1,3,0xff,0);
            if (iVar15 != 0) {
              uVar12 = uVar12 | 1 << sVar16 + 2;
            }
          }
        }
        else {
          uVar12 = uVar12 | 0xc;
        }
        fVar3 = FLOAT_803e7ea4;
        dVar20 = (double)FLOAT_803e7fcc;
        if (uVar12 != 0xf) {
          *(float *)(iVar17 + 0x564) = FLOAT_803e7ea4;
          *(float *)(iVar17 + 0x560) = fVar3;
          *(float *)(iVar17 + 0x568) = fVar3;
          iVar15 = (int)(short)DAT_803dc6a0;
          if ((iVar15 == 4) || (iVar15 == 0)) {
LAB_802a0f7c:
            *(ushort *)(iVar17 + 0x5a6) = *(ushort *)(iVar17 + 0x5a6) ^ 1;
          }
          else {
            uVar12 = countLeadingZeros(0xc - iVar15);
            uVar10 = countLeadingZeros(8 - iVar15);
            if ((uVar12 | uVar10) >> 5 != 0) goto LAB_802a0f7c;
          }
          if (*(short *)(iVar17 + 0x5a6) == 0) {
            DAT_803dc6a0 = 0x16;
          }
          else {
            DAT_803dc6a0 = 0x15;
          }
          if ((*(short *)(iVar11 + 0xa0) == DAT_80332f72) ||
             (*(short *)(iVar11 + 0xa0) == DAT_80332f74)) {
            DAT_803dc6a2 = DAT_803dc6a0;
            *(float *)(iVar11 + 0x98) = (float)in_f31;
          }
          dVar20 = (double)FLOAT_803e7ff8;
        }
      }
    }
    if ((DAT_803dc6a0 != 0x15) && (DAT_803dc6a0 != 0x16)) {
      if ((double)FLOAT_803e7ea4 <= dVar20) {
        if ((double)FLOAT_803e7ea4 < dVar20) {
          dVar20 = (double)(FLOAT_803e8004 * (float)puVar14[0xa6] + FLOAT_803e8000);
        }
      }
      else {
        dVar20 = -(double)(FLOAT_803e8004 * (float)puVar14[0xa6] + FLOAT_803e8000);
      }
    }
    FUN_802a13f4(iVar11,puVar14);
  }
  puVar14[0xa8] = (uint)(float)dVar20;
  if ((int)(short)DAT_803dc6a2 != (int)(short)DAT_803dc6a0) {
    FUN_80030334((double)FLOAT_803e7ea4,iVar11,
                 (int)*(short *)(&DAT_80332f48 + (short)DAT_803dc6a0 * 2),1);
  }
  fVar3 = *(float *)(iVar11 + 0x98);
  (**(code **)(*DAT_803dca50 + 0x2c))
            ((double)(*(float *)(iVar17 + 0x564) * fVar3 + *(float *)(iVar11 + 0xc)),
             (double)(*(float *)(iVar17 + 0x560) * fVar3 + *(float *)(iVar11 + 0x10)),
             (double)(*(float *)(iVar17 + 0x568) * fVar3 + *(float *)(iVar11 + 0x14)));
  FUN_802ab5a4(iVar11,iVar17,5);
  uVar18 = 0;
LAB_802a10dc:
  __psq_l0(auStack8,uVar19);
  __psq_l1(auStack8,uVar19);
  __psq_l0(auStack24,uVar19);
  __psq_l1(auStack24,uVar19);
  __psq_l0(auStack40,uVar19);
  __psq_l1(auStack40,uVar19);
  __psq_l0(auStack56,uVar19);
  __psq_l1(auStack56,uVar19);
  FUN_80286118(uVar18);
  return;
}

