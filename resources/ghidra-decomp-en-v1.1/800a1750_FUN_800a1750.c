// Function: FUN_800a1750
// Entry: 800a1750
// Size: 2512 bytes

/* WARNING: Removing unreachable block (ram,0x800a2100) */
/* WARNING: Removing unreachable block (ram,0x800a20f8) */
/* WARNING: Removing unreachable block (ram,0x800a1768) */
/* WARNING: Removing unreachable block (ram,0x800a1760) */

void FUN_800a1750(void)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  float *pfVar11;
  int iVar12;
  uint uVar13;
  short *psVar14;
  uint in_r6;
  int in_r7;
  uint uVar15;
  uint uVar16;
  int iVar17;
  uint unaff_r27;
  undefined4 *puVar18;
  int *piVar19;
  double in_f30;
  double dVar20;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined local_108;
  undefined local_107;
  undefined local_106 [2];
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  ushort local_ec;
  ushort local_ea;
  ushort local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float afStack_d4 [12];
  float afStack_a4 [17];
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar5 = FUN_80286824();
  uVar16 = 0;
  uVar15 = 0;
  if (in_r7 == 0) {
    FUN_80089b54(0,local_106,&local_107,&local_108);
  }
  else {
    FUN_80089b54((uint)*(byte *)(in_r7 + 0xf2),local_106,&local_107,&local_108);
  }
  FUN_80259288(0);
  iVar6 = FUN_80008b4c(-1);
  if ((short)iVar6 != 1) {
    puVar7 = FUN_8000facc();
    iVar6 = 0;
    piVar19 = &DAT_8039ce58;
    do {
      iVar8 = *piVar19;
      if (((((iVar8 != 0) && (*(short *)(iVar8 + 0x10c) != -1)) &&
           (((in_r6 & 0xff) == 0 || ((*(uint *)(iVar8 + 0xa4) & 0x2000) != 0)))) &&
          (((in_r6 & 0xff) == 0 || (*(int *)(iVar8 + 4) == in_r7)))) &&
         (((in_r6 & 0xff) != 0 || ((*(uint *)(iVar8 + 0xa4) & 0x2000) == 0)))) {
        if ((*(uint *)(iVar8 + 0xa4) & 0x800) != 0) {
          *(undefined *)(iVar8 + 0x13e) = 0;
        }
        bVar3 = false;
        iVar8 = *piVar19;
        iVar12 = iVar8 + (uint)*(byte *)(iVar8 + 0x130) * 4;
        iVar17 = *(int *)(iVar12 + 0x78);
        iVar12 = *(int *)(iVar12 + 0x84);
        local_e0 = FLOAT_803e00b0;
        local_dc = FLOAT_803e00b0;
        local_d8 = FLOAT_803e00b0;
        local_e4 = FLOAT_803e00b4;
        local_e8 = 0;
        local_ea = 0;
        local_f8 = *(float *)(iVar8 + 0x60);
        local_f4 = *(float *)(iVar8 + 100);
        local_f0 = *(float *)(iVar8 + 0x68);
        uVar13 = *(uint *)(iVar8 + 0xa4) & 4;
        if ((uVar13 != 0) && (FLOAT_803e00b0 == local_f0 + local_f8 + local_f4)) {
          bVar3 = true;
        }
        if (((uVar13 != 0) && (!bVar3)) && (*(ushort **)(iVar8 + 4) != (ushort *)0x0)) {
          local_ec = **(ushort **)(iVar8 + 4);
          local_ea = *(undefined2 *)(*(int *)(*piVar19 + 4) + 2);
          local_e8 = *(undefined2 *)(*(int *)(*piVar19 + 4) + 4);
          FUN_80021b8c(&local_ec,&local_f8);
        }
        local_104 = FLOAT_803e00b0;
        local_100 = FLOAT_803e00b0;
        local_fc = FLOAT_803e00b0;
        iVar8 = *piVar19;
        if ((*(uint *)(iVar8 + 0xa4) & 1) == 0) {
          iVar9 = *(int *)(iVar8 + 4);
          if (iVar9 == 0) {
            local_104 = *(float *)(iVar8 + 0x18);
            local_100 = *(float *)(iVar8 + 0x1c);
            local_fc = *(float *)(iVar8 + 0x20);
            FUN_8000dd94((float *)(iVar8 + 0x18),&local_104,*(char *)(iVar8 + 0x135));
          }
          else {
            local_104 = *(float *)(iVar9 + 0x18);
            local_100 = *(float *)(iVar9 + 0x1c);
            local_fc = *(float *)(iVar9 + 0x20);
          }
        }
        if ((FLOAT_803e00d0 < local_104) || (local_104 < FLOAT_803e00d4)) {
          local_104 = -FLOAT_803dda58;
        }
        if ((FLOAT_803e00d0 < local_100) || (local_100 < FLOAT_803e00d4)) {
          local_100 = FLOAT_803e00b0;
        }
        if ((FLOAT_803e00d0 < local_fc) || (local_fc < FLOAT_803e00d4)) {
          local_fc = -FLOAT_803dda5c;
        }
        local_e0 = local_104 + local_f8;
        local_dc = local_100 + local_f4;
        local_d8 = local_fc + local_f0;
        iVar8 = *piVar19;
        if ((*(uint *)(iVar8 + 0xa4) & 0x400000) == 0) {
          local_e4 = FLOAT_803e00dc * *(float *)(iVar8 + 0xd4);
        }
        else {
          dVar20 = (double)(FLOAT_803e00d8 * *(float *)(iVar8 + 0xd4));
          uStack_5c = FUN_80022264(1,10);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          local_e4 = (float)(dVar20 + (double)(float)(dVar20 / (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack_5c) - DOUBLE_803e00c8)));
        }
        iVar8 = *piVar19;
        if ((*(uint *)(iVar8 + 0xa4) & 0x80000) == 0) {
          if ((bVar3) && (psVar14 = *(short **)(iVar8 + 4), psVar14 != (short *)0x0)) {
            local_e8 = *(short *)(iVar8 + 0x106) + psVar14[2];
            local_ea = *(short *)(iVar8 + 0x108) + psVar14[1];
            local_ec = *(short *)(iVar8 + 0x10a) + *psVar14;
          }
          else if (bVar3) {
            local_e8 = *(short *)(iVar8 + 0x106) + *(short *)(iVar8 + 0x10);
            iVar8 = *piVar19;
            local_ea = *(short *)(iVar8 + 0x108) + *(short *)(iVar8 + 0xe);
            local_ec = *(short *)(iVar8 + 0x10a) + *(short *)(iVar8 + 0xc);
          }
          else {
            local_e8 = *(ushort *)(iVar8 + 0x106);
            local_ea = *(ushort *)(*piVar19 + 0x108);
            local_ec = *(ushort *)(*piVar19 + 0x10a);
          }
        }
        else {
          puVar10 = *(ushort **)(iVar8 + 4);
          local_e8 = puVar10[2];
          local_ea = puVar10[1];
          local_ec = *puVar10;
        }
        if (((*(uint *)(*piVar19 + 0xa4) & 0x1000) != 0) &&
           (iVar8 = *(int *)(*piVar19 + 4), iVar8 != 0)) {
          fVar1 = *(float *)(puVar7 + 0x22) - *(float *)(iVar8 + 0x18);
          fVar2 = *(float *)(puVar7 + 0x26) - *(float *)(iVar8 + 0x20);
          FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
          uStack_5c = FUN_80021884();
          uStack_5c = uStack_5c & 0xffff;
          local_60 = 0x43300000;
          iVar8 = (int)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e00c0);
          local_58 = (longlong)iVar8;
          local_ec = local_ec + (short)iVar8;
        }
        local_e0 = local_e0 - FLOAT_803dda58;
        local_d8 = local_d8 - FLOAT_803dda5c;
        FUN_80021fac(afStack_a4,&local_ec);
        FUN_800216cc(afStack_a4,afStack_d4);
        pfVar11 = (float *)FUN_8000f56c();
        FUN_80247618(pfVar11,afStack_d4,afStack_d4);
        FUN_8025d80c(afStack_d4,0);
        iVar8 = *piVar19;
        if ((*(int *)(iVar8 + 0x98) != 0) &&
           (unaff_r27 = (int)(uint)*(ushort *)(*(int *)(iVar8 + 0x98) + 0x10) >> 8,
           *(char *)(iVar8 + 0x132) != '\0')) {
          *(char *)(iVar8 + 0x133) = *(char *)(iVar8 + 0x133) + -1;
          iVar8 = *piVar19;
          if (*(char *)(iVar8 + 0x133) == '\0') {
            *(char *)(iVar8 + 0x133) = (char)(0x3c / *(byte *)(iVar8 + 0x132));
            *(char *)(*piVar19 + 0x131) = *(char *)(*piVar19 + 0x131) + '\x01';
            if (unaff_r27 <= *(byte *)(*piVar19 + 0x131)) {
              *(undefined *)(*piVar19 + 0x131) = 0;
            }
          }
        }
        uVar13 = *(uint *)(*piVar19 + 0xa4);
        if ((uVar13 & 0x10000000) == 0) {
          iVar8 = *(int *)(*piVar19 + 4);
          if ((iVar8 == 0) || ((uVar13 & 0x4000) == 0)) {
            FUN_8005d294(uVar5,0xff,0xff,0xff,0xff);
          }
          else {
            FUN_8005d294(uVar5,0xff,0xff,0xff,*(undefined *)(iVar8 + 0x37));
          }
        }
        else {
          FUN_8005d294(uVar5,local_106[0],local_107,local_108,0xff);
        }
        iVar8 = *piVar19;
        puVar18 = *(undefined4 **)(iVar8 + 0x98);
        if (puVar18 != (undefined4 *)0x0) {
          uVar15 = (uint)*(byte *)(iVar8 + 0x131);
          uVar16 = uVar15 + 1 & 0xff;
          if ((int)(unaff_r27 - 1) < (int)uVar16) {
            uVar16 = 0;
          }
        }
        uVar13 = *(uint *)(iVar8 + 0xa4);
        if (((uVar13 & 0x1000000) == 0) ||
           ((*(char *)(iVar8 + 0x13e) == '\0' && ((uVar13 & 0x400) == 0)))) {
          if ((uVar13 & 0x2000000) == 0) {
            if ((uVar13 & 0x4000000) != 0) {
              FUN_80079b3c();
              FUN_8007986c();
              FUN_800793d0();
              FUN_80079980();
            }
          }
          else {
            FUN_80079b3c();
            FUN_8007904c();
            FUN_80079980();
          }
        }
        else {
          iVar9 = 0;
          if (uVar16 != 0) {
            if ((8 < uVar16) && (uVar13 = uVar16 - 1 >> 3, 0 < (int)(uVar16 - 8))) {
              do {
                puVar18 = *(undefined4 **)
                           **(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar18;
                iVar9 = iVar9 + 8;
                uVar13 = uVar13 - 1;
              } while (uVar13 != 0);
            }
            iVar4 = uVar16 - iVar9;
            if (iVar9 < (int)uVar16) {
              do {
                puVar18 = (undefined4 *)*puVar18;
                iVar4 = iVar4 + -1;
              } while (iVar4 != 0);
            }
          }
          FUN_8005d264(uVar5,0xff,0xff,0xff,-1 - *(char *)(iVar8 + 0x133) * *(char *)(iVar8 + 0x134)
                      );
          FUN_80079b3c();
          FUN_800794a4();
          FUN_80078f78();
          FUN_80079980();
          FUN_8004c460((int)puVar18,1);
        }
        iVar8 = *piVar19;
        if (((*(uint *)(iVar8 + 0xa4) & 0x5000000) != 0) &&
           ((*(char *)(iVar8 + 0x13e) != '\0' || ((*(uint *)(iVar8 + 0xa4) & 0x400) != 0)))) {
          puVar18 = *(undefined4 **)(iVar8 + 0x98);
          iVar8 = 0;
          if (uVar15 != 0) {
            if ((8 < uVar15) && (uVar13 = uVar15 - 1 >> 3, 0 < (int)(uVar15 - 8))) {
              do {
                puVar18 = *(undefined4 **)
                           **(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar18;
                iVar8 = iVar8 + 8;
                uVar13 = uVar13 - 1;
              } while (uVar13 != 0);
            }
            iVar9 = uVar15 - iVar8;
            if (iVar8 < (int)uVar15) {
              do {
                puVar18 = (undefined4 *)*puVar18;
                iVar9 = iVar9 + -1;
              } while (iVar9 != 0);
            }
          }
          FUN_8004c460((int)puVar18,0);
        }
        uVar13 = *(uint *)(*piVar19 + 0xa4);
        if ((uVar13 & 0x100) == 0) {
          if (((uVar13 & 0x10) == 0) || ((uVar13 & 0x80) == 0)) {
            if ((uVar13 & 0x80) == 0) {
              if ((uVar13 & 0x10) == 0) {
                FUN_80078cc8();
              }
              else {
                FUN_80078bf8();
              }
            }
            else {
              FUN_80078cc8();
            }
          }
          else {
            FUN_80078bf8();
          }
        }
        else {
          FUN_80078cc8();
        }
        if ((*(uint *)(*piVar19 + 0xa4) & 0x40) == 0) {
          FUN_80259288(0);
        }
        else {
          FUN_80259288(1);
        }
        if ((*(char *)(*piVar19 + 0x13e) != '\0') || ((*(uint *)(*piVar19 + 0xa4) & 0x400) != 0)) {
          iVar8 = 0;
          while( true ) {
            iVar9 = *piVar19;
            if ((int)(uint)*(byte *)(iVar9 + 0x136) <= iVar8) break;
            if ((*(uint *)(iVar9 + 0xa4) & 0x8000000) == 0) {
              FUN_8005d108(iVar17,iVar12,(int)*(short *)(iVar9 + 0xec));
            }
            else {
              FUN_8005d108(iVar17,iVar12,
                           (int)*(short *)(iVar9 + 0xec) / (int)(uint)*(byte *)(iVar9 + 0x136));
            }
            iVar9 = *piVar19;
            iVar17 = iVar17 + (uint)*(byte *)(iVar9 + 0x137) * 0x10;
            if ((*(uint *)(iVar9 + 0xa4) & 0x8000000) != 0) {
              iVar12 = iVar12 + ((int)*(short *)(iVar9 + 0xec) / (int)(uint)*(byte *)(iVar9 + 0x136)
                                ) * 0x10;
            }
            iVar8 = iVar8 + 1;
          }
        }
        FUN_80054470();
        *(char *)(*piVar19 + 0x130) = '\x01' - *(char *)(*piVar19 + 0x130);
      }
      piVar19 = piVar19 + 1;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x32);
  }
  FUN_80286870();
  return;
}

