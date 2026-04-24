// Function: FUN_800a14c4
// Entry: 800a14c4
// Size: 2512 bytes

/* WARNING: Removing unreachable block (ram,0x800a1e6c) */
/* WARNING: Removing unreachable block (ram,0x800a1e74) */

void FUN_800a14c4(void)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar9;
  int iVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  undefined4 uVar8;
  int iVar10;
  uint uVar11;
  uint in_r6;
  int in_r7;
  uint uVar12;
  uint uVar13;
  int iVar14;
  uint unaff_r27;
  int iVar15;
  undefined4 *puVar16;
  int *piVar17;
  undefined4 uVar18;
  undefined8 in_f30;
  double dVar19;
  double dVar20;
  undefined8 in_f31;
  double dVar21;
  undefined local_108;
  undefined local_107;
  undefined local_106 [2];
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  short local_ec;
  short local_ea;
  short local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  undefined auStack212 [48];
  undefined auStack164 [68];
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar18 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar3 = FUN_802860c0();
  uVar13 = 0;
  uVar12 = 0;
  if (in_r7 == 0) {
    FUN_800898c8(0,local_106,&local_107,&local_108);
  }
  else {
    FUN_800898c8(*(undefined *)(in_r7 + 0xf2),local_106,&local_107,&local_108);
  }
  FUN_80258b24(0);
  sVar9 = FUN_80008b4c(0xffffffff);
  if (sVar9 == 1) {
    uVar3 = 1;
  }
  else {
    iVar4 = FUN_8000faac();
    iVar15 = 0;
    piVar17 = &DAT_8039c1f8;
    do {
      iVar5 = *piVar17;
      if (((((iVar5 != 0) && (*(short *)(iVar5 + 0x10c) != -1)) &&
           (((in_r6 & 0xff) == 0 || ((*(uint *)(iVar5 + 0xa4) & 0x2000) != 0)))) &&
          (((in_r6 & 0xff) == 0 || (*(int *)(iVar5 + 4) == in_r7)))) &&
         (((in_r6 & 0xff) != 0 || ((*(uint *)(iVar5 + 0xa4) & 0x2000) == 0)))) {
        if ((*(uint *)(iVar5 + 0xa4) & 0x800) != 0) {
          *(undefined *)(iVar5 + 0x13e) = 0;
        }
        bVar1 = false;
        iVar5 = *piVar17;
        iVar10 = iVar5 + (uint)*(byte *)(iVar5 + 0x130) * 4;
        iVar14 = *(int *)(iVar10 + 0x78);
        iVar10 = *(int *)(iVar10 + 0x84);
        local_e0 = FLOAT_803df430;
        local_dc = FLOAT_803df430;
        local_d8 = FLOAT_803df430;
        local_e4 = FLOAT_803df434;
        local_e8 = 0;
        local_ea = 0;
        local_f8 = *(float *)(iVar5 + 0x60);
        local_f4 = *(float *)(iVar5 + 100);
        local_f0 = *(float *)(iVar5 + 0x68);
        uVar11 = *(uint *)(iVar5 + 0xa4) & 4;
        if ((uVar11 != 0) && (FLOAT_803df430 == local_f0 + local_f8 + local_f4)) {
          bVar1 = true;
        }
        if (((uVar11 != 0) && (!bVar1)) && (*(short **)(iVar5 + 4) != (short *)0x0)) {
          local_ec = **(short **)(iVar5 + 4);
          local_ea = *(undefined2 *)(*(int *)(*piVar17 + 4) + 2);
          local_e8 = *(undefined2 *)(*(int *)(*piVar17 + 4) + 4);
          FUN_80021ac8(&local_ec,&local_f8);
        }
        local_104 = FLOAT_803df430;
        local_100 = FLOAT_803df430;
        local_fc = FLOAT_803df430;
        iVar5 = *piVar17;
        if ((*(uint *)(iVar5 + 0xa4) & 1) == 0) {
          iVar6 = *(int *)(iVar5 + 4);
          if (iVar6 == 0) {
            local_104 = *(float *)(iVar5 + 0x18);
            local_100 = *(float *)(iVar5 + 0x1c);
            local_fc = *(float *)(iVar5 + 0x20);
            FUN_8000dd74(iVar5 + 0x18,&local_104,*(undefined *)(iVar5 + 0x135));
          }
          else {
            local_104 = *(float *)(iVar6 + 0x18);
            local_100 = *(float *)(iVar6 + 0x1c);
            local_fc = *(float *)(iVar6 + 0x20);
          }
        }
        if ((FLOAT_803df450 < local_104) || (local_104 < FLOAT_803df454)) {
          local_104 = -FLOAT_803dcdd8;
        }
        if ((FLOAT_803df450 < local_100) || (local_100 < FLOAT_803df454)) {
          local_100 = FLOAT_803df430;
        }
        if ((FLOAT_803df450 < local_fc) || (local_fc < FLOAT_803df454)) {
          local_fc = -FLOAT_803dcddc;
        }
        local_e0 = local_104 + local_f8;
        local_dc = local_100 + local_f4;
        local_d8 = local_fc + local_f0;
        iVar5 = *piVar17;
        if ((*(uint *)(iVar5 + 0xa4) & 0x400000) == 0) {
          local_e4 = FLOAT_803df45c * *(float *)(iVar5 + 0xd4);
        }
        else {
          dVar19 = (double)(FLOAT_803df458 * *(float *)(iVar5 + 0xd4));
          uStack92 = FUN_800221a0(1,10);
          uStack92 = uStack92 ^ 0x80000000;
          local_60 = 0x43300000;
          local_e4 = (float)(dVar19 + (double)(float)(dVar19 / (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack92) - DOUBLE_803df448)));
        }
        iVar5 = *piVar17;
        if ((*(uint *)(iVar5 + 0xa4) & 0x80000) == 0) {
          if ((bVar1) && (psVar7 = *(short **)(iVar5 + 4), psVar7 != (short *)0x0)) {
            local_e8 = *(short *)(iVar5 + 0x106) + psVar7[2];
            local_ea = *(short *)(iVar5 + 0x108) + psVar7[1];
            local_ec = *(short *)(iVar5 + 0x10a) + *psVar7;
          }
          else if (bVar1) {
            local_e8 = *(short *)(iVar5 + 0x106) + *(short *)(iVar5 + 0x10);
            iVar5 = *piVar17;
            local_ea = *(short *)(iVar5 + 0x108) + *(short *)(iVar5 + 0xe);
            local_ec = *(short *)(iVar5 + 0x10a) + *(short *)(iVar5 + 0xc);
          }
          else {
            local_e8 = *(short *)(iVar5 + 0x106);
            local_ea = *(short *)(*piVar17 + 0x108);
            local_ec = *(short *)(*piVar17 + 0x10a);
          }
        }
        else {
          psVar7 = *(short **)(iVar5 + 4);
          local_e8 = psVar7[2];
          local_ea = psVar7[1];
          local_ec = *psVar7;
        }
        if (((*(uint *)(*piVar17 + 0xa4) & 0x1000) != 0) &&
           (iVar5 = *(int *)(*piVar17 + 4), iVar5 != 0)) {
          dVar21 = (double)(*(float *)(iVar4 + 0x44) - *(float *)(iVar5 + 0x18));
          dVar20 = (double)(*(float *)(iVar4 + 0x4c) - *(float *)(iVar5 + 0x20));
          dVar19 = (double)FUN_802931a0((double)(float)(dVar21 * dVar21 +
                                                       (double)(float)(dVar20 * dVar20)));
          if (dVar19 != (double)FLOAT_803df430) {
            dVar21 = (double)(float)(dVar21 / dVar19);
            dVar20 = (double)(float)(dVar20 / dVar19);
          }
          uStack92 = FUN_800217c0(dVar21,dVar20);
          uStack92 = uStack92 & 0xffff;
          local_60 = 0x43300000;
          iVar5 = (int)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df440);
          local_58 = (longlong)iVar5;
          local_ec = local_ec + (short)iVar5;
        }
        local_e0 = local_e0 - FLOAT_803dcdd8;
        local_d8 = local_d8 - FLOAT_803dcddc;
        FUN_80021ee8(auStack164,&local_ec);
        FUN_80021608(auStack164,auStack212);
        uVar8 = FUN_8000f54c();
        FUN_80246eb4(uVar8,auStack212,auStack212);
        FUN_8025d0a8(auStack212,0);
        iVar5 = *piVar17;
        if ((*(int *)(iVar5 + 0x98) != 0) &&
           (unaff_r27 = (int)(uint)*(ushort *)(*(int *)(iVar5 + 0x98) + 0x10) >> 8,
           *(char *)(iVar5 + 0x132) != '\0')) {
          *(char *)(iVar5 + 0x133) = *(char *)(iVar5 + 0x133) + -1;
          iVar5 = *piVar17;
          if (*(char *)(iVar5 + 0x133) == '\0') {
            *(char *)(iVar5 + 0x133) = (char)(0x3c / *(byte *)(iVar5 + 0x132));
            *(char *)(*piVar17 + 0x131) = *(char *)(*piVar17 + 0x131) + '\x01';
            if (unaff_r27 <= *(byte *)(*piVar17 + 0x131)) {
              *(undefined *)(*piVar17 + 0x131) = 0;
            }
          }
        }
        uVar11 = *(uint *)(*piVar17 + 0xa4);
        if ((uVar11 & 0x10000000) == 0) {
          iVar5 = *(int *)(*piVar17 + 4);
          if ((iVar5 == 0) || ((uVar11 & 0x4000) == 0)) {
            FUN_8005d118(uVar3,0xff,0xff,0xff,0xff);
          }
          else {
            FUN_8005d118(uVar3,0xff,0xff,0xff,*(undefined *)(iVar5 + 0x37));
          }
        }
        else {
          FUN_8005d118(uVar3,local_106[0],local_107,local_108,0xff);
        }
        iVar5 = *piVar17;
        puVar16 = *(undefined4 **)(iVar5 + 0x98);
        if (puVar16 != (undefined4 *)0x0) {
          uVar12 = (uint)*(byte *)(iVar5 + 0x131);
          uVar13 = uVar12 + 1 & 0xff;
          if ((int)(unaff_r27 - 1) < (int)uVar13) {
            uVar13 = 0;
          }
        }
        uVar11 = *(uint *)(iVar5 + 0xa4);
        if (((uVar11 & 0x1000000) == 0) ||
           ((*(char *)(iVar5 + 0x13e) == '\0' && ((uVar11 & 0x400) == 0)))) {
          if ((uVar11 & 0x2000000) == 0) {
            if ((uVar11 & 0x4000000) != 0) {
              FUN_800799c0();
              FUN_800796f0();
              FUN_80079254();
              FUN_80079804();
            }
          }
          else {
            FUN_800799c0();
            FUN_80078ed0();
            FUN_80079804();
          }
        }
        else {
          iVar6 = 0;
          if (uVar13 != 0) {
            if ((8 < uVar13) && (uVar11 = uVar13 - 1 >> 3, 0 < (int)(uVar13 - 8))) {
              do {
                puVar16 = *(undefined4 **)
                           **(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar16;
                iVar6 = iVar6 + 8;
                uVar11 = uVar11 - 1;
              } while (uVar11 != 0);
            }
            iVar2 = uVar13 - iVar6;
            if (iVar6 < (int)uVar13) {
              do {
                puVar16 = (undefined4 *)*puVar16;
                iVar2 = iVar2 + -1;
              } while (iVar2 != 0);
            }
          }
          FUN_8005d0e8(uVar3,0xff,0xff,0xff,-1 - *(char *)(iVar5 + 0x133) * *(char *)(iVar5 + 0x134)
                      );
          FUN_800799c0();
          FUN_80079328();
          FUN_80078dfc();
          FUN_80079804();
          FUN_8004c2e4(puVar16,1);
        }
        iVar5 = *piVar17;
        if (((*(uint *)(iVar5 + 0xa4) & 0x5000000) != 0) &&
           ((*(char *)(iVar5 + 0x13e) != '\0' || ((*(uint *)(iVar5 + 0xa4) & 0x400) != 0)))) {
          puVar16 = *(undefined4 **)(iVar5 + 0x98);
          iVar5 = 0;
          if (uVar12 != 0) {
            if ((8 < uVar12) && (uVar11 = uVar12 - 1 >> 3, 0 < (int)(uVar12 - 8))) {
              do {
                puVar16 = *(undefined4 **)
                           **(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar16;
                iVar5 = iVar5 + 8;
                uVar11 = uVar11 - 1;
              } while (uVar11 != 0);
            }
            iVar6 = uVar12 - iVar5;
            if (iVar5 < (int)uVar12) {
              do {
                puVar16 = (undefined4 *)*puVar16;
                iVar5 = iVar5 + 1;
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
            }
          }
          FUN_8004c2e4(puVar16,0,uVar12,iVar5);
        }
        uVar11 = *(uint *)(*piVar17 + 0xa4);
        if ((uVar11 & 0x100) == 0) {
          if (((uVar11 & 0x10) == 0) || ((uVar11 & 0x80) == 0)) {
            if ((uVar11 & 0x80) == 0) {
              if ((uVar11 & 0x10) == 0) {
                FUN_80078b4c();
              }
              else {
                FUN_80078a7c();
              }
            }
            else {
              FUN_80078b4c();
            }
          }
          else {
            FUN_80078a7c();
          }
        }
        else {
          FUN_80078b4c();
        }
        if ((*(uint *)(*piVar17 + 0xa4) & 0x40) == 0) {
          FUN_80258b24(0);
        }
        else {
          FUN_80258b24(1);
        }
        if ((*(char *)(*piVar17 + 0x13e) != '\0') || ((*(uint *)(*piVar17 + 0xa4) & 0x400) != 0)) {
          iVar5 = 0;
          while( true ) {
            iVar6 = *piVar17;
            if ((int)(uint)*(byte *)(iVar6 + 0x136) <= iVar5) break;
            if ((*(uint *)(iVar6 + 0xa4) & 0x8000000) == 0) {
              FUN_8005cf8c(iVar14,iVar10,(int)*(short *)(iVar6 + 0xec));
            }
            else {
              FUN_8005cf8c(iVar14,iVar10,
                           (int)*(short *)(iVar6 + 0xec) / (int)(uint)*(byte *)(iVar6 + 0x136));
            }
            iVar6 = *piVar17;
            iVar14 = iVar14 + (uint)*(byte *)(iVar6 + 0x137) * 0x10;
            if ((*(uint *)(iVar6 + 0xa4) & 0x8000000) != 0) {
              iVar10 = iVar10 + ((int)*(short *)(iVar6 + 0xec) / (int)(uint)*(byte *)(iVar6 + 0x136)
                                ) * 0x10;
            }
            iVar5 = iVar5 + 1;
          }
        }
        FUN_800542f4();
        *(char *)(*piVar17 + 0x130) = '\x01' - *(char *)(*piVar17 + 0x130);
      }
      piVar17 = piVar17 + 1;
      iVar15 = iVar15 + 1;
    } while (iVar15 < 0x32);
    uVar3 = 0;
  }
  __psq_l0(auStack8,uVar18);
  __psq_l1(auStack8,uVar18);
  __psq_l0(auStack24,uVar18);
  __psq_l1(auStack24,uVar18);
  FUN_8028610c(uVar3);
  return;
}

