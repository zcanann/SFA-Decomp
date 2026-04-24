// Function: FUN_80017508
// Entry: 80017508
// Size: 4104 bytes

/* WARNING: Removing unreachable block (ram,0x800184f0) */
/* WARNING: Removing unreachable block (ram,0x800184e8) */
/* WARNING: Removing unreachable block (ram,0x800184e0) */
/* WARNING: Removing unreachable block (ram,0x800184d8) */
/* WARNING: Removing unreachable block (ram,0x800184d0) */
/* WARNING: Removing unreachable block (ram,0x800184c8) */
/* WARNING: Removing unreachable block (ram,0x800184c0) */
/* WARNING: Removing unreachable block (ram,0x800184b8) */
/* WARNING: Removing unreachable block (ram,0x800184b0) */
/* WARNING: Removing unreachable block (ram,0x800184a8) */
/* WARNING: Removing unreachable block (ram,0x80017560) */
/* WARNING: Removing unreachable block (ram,0x80017558) */
/* WARNING: Removing unreachable block (ram,0x80017550) */
/* WARNING: Removing unreachable block (ram,0x80017548) */
/* WARNING: Removing unreachable block (ram,0x80017540) */
/* WARNING: Removing unreachable block (ram,0x80017538) */
/* WARNING: Removing unreachable block (ram,0x80017530) */
/* WARNING: Removing unreachable block (ram,0x80017528) */
/* WARNING: Removing unreachable block (ram,0x80017520) */
/* WARNING: Removing unreachable block (ram,0x80017518) */
/* WARNING: Removing unreachable block (ram,0x80017a54) */

void FUN_80017508(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  byte bVar1;
  undefined *puVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  uint *puVar10;
  byte *pbVar11;
  uint uVar12;
  int unaff_r28;
  uint uVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  uint uVar17;
  double extraout_f1;
  double dVar18;
  double dVar19;
  double dVar20;
  double in_f22;
  double dVar21;
  double in_f23;
  double dVar22;
  double in_f24;
  double in_f25;
  double dVar23;
  double in_f26;
  double dVar24;
  double in_f27;
  double dVar25;
  double in_f28;
  double dVar26;
  double in_f29;
  double dVar27;
  double in_f30;
  double dVar28;
  double in_f31;
  double dVar29;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar30;
  int local_158;
  int local_154;
  int local_150;
  uint local_14c;
  int local_148;
  undefined4 uStack_144;
  float local_140;
  int local_13c;
  uint local_138 [8];
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined4 local_e0;
  uint uStack_dc;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  uVar30 = FUN_80286824();
  iVar5 = (int)((ulonglong)uVar30 >> 0x20);
  iVar9 = (int)uVar30;
  iVar14 = 0;
  dVar23 = (double)FLOAT_803df384;
  if (DAT_803dd668 == 2) {
    uVar13 = 6;
  }
  else {
    uVar13 = (uint)(byte)(&DAT_802c7b54)[DAT_803dd664 * 8];
  }
  uVar12 = 0xffffffff;
  bVar4 = true;
  if ((iVar5 != 0) && (DAT_803dd66c[7] == 2)) {
    dVar21 = extraout_f1;
    if ((DAT_803dd664 != 4) &&
       (((param_6 == 1 && (iVar6 = FUN_800e8118(3), iVar6 != 0)) && (iVar9 == -0x7fd38340)))) {
      FUN_80018510(iVar5);
    }
    FUN_80018728(iVar5,&local_140,&uStack_144,(float *)0x0,(float *)0x0,0xffffffff);
    if (DAT_803dd63c == 0) {
      FUN_8005d294(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
      FUN_8005d264(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
      FUN_80079b3c();
      FUN_80079120();
      FUN_80079980();
      FUN_80078bf8();
    }
    local_118 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x14) ^ 0x80000000);
    dVar21 = (double)(float)(dVar21 + (double)(float)(local_118 - DOUBLE_803df378));
    local_110 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x16) ^ 0x80000000);
    dVar22 = (double)(float)(param_2 + (double)(float)(local_110 - DOUBLE_803df378));
LAB_8001848c:
    pbVar11 = (byte *)(iVar5 + iVar14);
    uVar8 = FUN_80015cf0(pbVar11,&local_13c);
    if (uVar8 != 0) {
      iVar14 = iVar14 + local_13c;
      bVar3 = false;
      if ((0xdfff < uVar8) && (uVar8 < 0xf900)) goto code_r0x800176f0;
      if (param_6 == 0) {
        DAT_803dd618 = DAT_803dd618 + 1;
      }
      goto LAB_80017a30;
    }
  }
  FUN_80286870();
  return;
code_r0x800176f0:
  puVar10 = &DAT_802c8e70;
  iVar6 = 0x17;
  do {
    if (*puVar10 == uVar8) {
      uVar7 = puVar10[1];
      goto LAB_80017740;
    }
    if (puVar10[2] == uVar8) {
      uVar7 = puVar10[3];
      goto LAB_80017740;
    }
    puVar10 = puVar10 + 4;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  uVar7 = 0;
LAB_80017740:
  iVar6 = 0;
  if (0 < (int)uVar7) {
    if (8 < (int)uVar7) {
      puVar10 = local_138;
      uVar17 = uVar7 - 1 >> 3;
      if (0 < (int)(uVar7 - 8)) {
        do {
          *puVar10 = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14),
                                    *(undefined *)(iVar5 + iVar14 + 1));
          puVar10[1] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 2),
                                      *(undefined *)(iVar5 + iVar14 + 3));
          puVar10[2] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 4),
                                      *(undefined *)(iVar5 + iVar14 + 5));
          puVar10[3] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 6),
                                      *(undefined *)(iVar5 + iVar14 + 7));
          puVar10[4] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 8),
                                      *(undefined *)(iVar5 + iVar14 + 9));
          puVar10[5] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 10),
                                      *(undefined *)(iVar5 + iVar14 + 0xb));
          iVar15 = iVar14 + 0xe;
          puVar10[6] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 0xc),
                                      *(undefined *)(iVar5 + iVar14 + 0xd));
          iVar16 = iVar14 + 0xf;
          iVar14 = iVar14 + 0x10;
          puVar10[7] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar15),*(undefined *)(iVar5 + iVar16))
          ;
          puVar10 = puVar10 + 8;
          iVar6 = iVar6 + 8;
          uVar17 = uVar17 - 1;
        } while (uVar17 != 0);
      }
    }
    puVar10 = local_138 + iVar6;
    iVar15 = uVar7 - iVar6;
    if (iVar6 < (int)uVar7) {
      do {
        iVar6 = iVar14 + 1;
        puVar2 = (undefined *)(iVar5 + iVar14);
        iVar14 = iVar14 + 2;
        *puVar10 = (uint)CONCAT11(*puVar2,*(undefined *)(iVar5 + iVar6));
        puVar10 = puVar10 + 1;
        iVar15 = iVar15 + -1;
      } while (iVar15 != 0);
    }
  }
  switch(uVar8) {
  case 0xf8f4:
    local_110 = (double)CONCAT44(0x43300000,local_138[0] ^ 0x80000000);
    FLOAT_803dd620 = (float)(local_110 - DOUBLE_803df378) * FLOAT_803df388;
    break;
  case 0xf8f7:
    uVar13 = local_138[0];
    break;
  case 0xf8f8:
    *(undefined *)(iVar9 + 0x12) = 0;
    bVar4 = true;
    break;
  case 0xf8f9:
    *(undefined *)(iVar9 + 0x12) = 1;
    bVar4 = true;
    break;
  case 0xf8fa:
    *(undefined *)(iVar9 + 0x12) = 2;
    bVar4 = true;
    break;
  case 0xf8fb:
    *(undefined *)(iVar9 + 0x12) = 3;
    bVar4 = true;
    break;
  case 0xf8ff:
    if (param_6 == 0) {
      DAT_803dd624 = (byte)(local_138[3] * (DAT_803dd624 + 1) >> 8);
      DAT_803dd625 = (undefined)local_138[2];
      DAT_803dd626 = (undefined)local_138[1];
      DAT_803dd627 = (undefined)local_138[0];
      if (DAT_803dd63c == 0) {
        FUN_8005d294(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
        FUN_8005d264(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
        FUN_80079b3c();
        FUN_80079120();
        FUN_80079980();
        FUN_80078bf8();
      }
    }
    bVar3 = true;
  }
  if (!bVar3) {
LAB_80017a30:
    if (bVar4) {
      bVar1 = *(byte *)(iVar9 + 0x12);
      if (bVar1 == 2) {
        dVar23 = (double)FLOAT_803df384;
        FUN_80018728(pbVar11,&local_140,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 8));
        local_118 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x14) ^ 0x80000000);
        dVar21 = (double)(((float)(local_110 - DOUBLE_803df370) - local_140) * FLOAT_803df38c +
                         (float)(local_118 - DOUBLE_803df378));
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          dVar23 = (double)FLOAT_803df384;
        }
        else {
          dVar23 = (double)FLOAT_803df384;
          FUN_80018728(pbVar11,&local_140,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
          local_110 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x14) ^ 0x80000000);
          local_118 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 8));
          dVar21 = (double)((float)(local_110 - DOUBLE_803df378) +
                           ((float)(local_118 - DOUBLE_803df370) - local_140));
        }
      }
      else if (bVar1 < 4) {
        FUN_80018728(pbVar11,&local_140,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
        iVar6 = 0;
        uVar7 = 0;
        while (uVar17 = FUN_80015cf0(pbVar11 + iVar6,&local_158), uVar17 != 0) {
          iVar6 = iVar6 + local_158;
          if (uVar17 == 0x20) {
            uVar7 = uVar7 + 1;
          }
          if ((0xdfff < uVar17) && (uVar17 < 0xf900)) {
            puVar10 = &DAT_802c8e70;
            iVar15 = 0x17;
            do {
              if (*puVar10 == uVar17) {
                uVar17 = puVar10[1];
                goto LAB_80017be8;
              }
              if (puVar10[2] == uVar17) {
                uVar17 = puVar10[3];
                goto LAB_80017be8;
              }
              puVar10 = puVar10 + 4;
              iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            uVar17 = 0;
LAB_80017be8:
            iVar6 = iVar6 + uVar17 * 2;
          }
        }
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 8));
        local_118 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        dVar23 = (double)(((float)(local_110 - DOUBLE_803df370) - local_140) /
                         (float)(local_118 - DOUBLE_803df378));
      }
      bVar4 = false;
    }
    puVar10 = (uint *)*DAT_803dd66c;
    for (iVar6 = DAT_803dd66c[2]; iVar6 != 0; iVar6 = iVar6 + -1) {
      if ((*puVar10 == uVar8) && (*(byte *)((int)puVar10 + 0xe) == uVar13)) goto LAB_80017c8c;
      puVar10 = puVar10 + 4;
    }
    puVar10 = (uint *)0x0;
LAB_80017c8c:
    if (puVar10 != (uint *)0x0) {
      if (uVar8 == 10) {
        dVar21 = (double)FLOAT_803df384;
        dVar22 = (double)(float)(dVar22 + param_3);
      }
      else if (uVar8 == 0x20) {
        local_110 = (double)CONCAT44(0x43300000,
                                     (uint)*(byte *)(puVar10 + 3) +
                                     (int)*(char *)(puVar10 + 2) + (int)*(char *)((int)puVar10 + 9)
                                     ^ 0x80000000);
        dVar21 = (double)(float)((double)(float)((double)FLOAT_803dd620 *
                                                 (double)(float)(local_110 - DOUBLE_803df378) +
                                                dVar21) + dVar23);
      }
      else {
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(puVar10 + 1) << 5 ^ 0x80000000);
        dVar25 = (double)(float)(local_110 - DOUBLE_803df378);
        local_118 = (double)CONCAT44(0x43300000,
                                     (uint)*(ushort *)((int)puVar10 + 6) << 5 ^ 0x80000000);
        dVar24 = (double)(float)(local_118 - DOUBLE_803df378);
        dVar18 = (double)FLOAT_803df390;
        local_108 = (double)CONCAT44(0x43300000,(int)*(char *)(puVar10 + 2) ^ 0x80000000);
        dVar29 = (double)(float)(dVar18 * (double)(float)(dVar21 + (double)((float)(local_108 -
                                                                                   DOUBLE_803df378)
                                                                           * FLOAT_803dd620)));
        local_100 = (double)CONCAT44(0x43300000,(int)*(char *)((int)puVar10 + 10) ^ 0x80000000);
        dVar28 = (double)(float)(dVar18 * (double)(float)(dVar22 + (double)((float)(local_100 -
                                                                                   DOUBLE_803df378)
                                                                           * FLOAT_803dd620)));
        local_f8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar10 + 3));
        dVar20 = dVar18 * (double)((float)(local_f8 - DOUBLE_803df370) * FLOAT_803dd620) + dVar29;
        dVar27 = (double)(float)dVar20;
        local_f0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)puVar10 + 0xd));
        dVar18 = dVar18 * (double)((float)(local_f0 - DOUBLE_803df370) * FLOAT_803dd620) + dVar28;
        dVar26 = (double)(float)dVar18;
        dVar19 = (double)FLOAT_803df384;
        if ((dVar29 < dVar19) && (dVar19 < dVar27)) {
          dVar25 = (double)(float)((double)FLOAT_803df394 * -dVar29 + dVar25);
          dVar29 = dVar19;
        }
        dVar19 = (double)FLOAT_803df384;
        if ((dVar28 < dVar19) && (dVar19 < dVar26)) {
          dVar24 = (double)(float)((double)FLOAT_803df394 * -dVar28 + dVar24);
          dVar28 = dVar19;
        }
        if (DAT_803dd63c == 0) {
          if (*(char *)((int)puVar10 + 0xe) == '\x03') {
            uVar8 = DAT_803dc02c << 2 ^ 0x80000000;
            local_e8 = (double)CONCAT44(0x43300000,uVar8);
            dVar28 = (double)(float)(dVar28 - (double)(float)(local_e8 - DOUBLE_803df378));
            local_f0 = (double)CONCAT44(0x43300000,uVar8);
            dVar26 = (double)(float)(dVar26 - (double)(float)(local_f0 - DOUBLE_803df378));
            FUN_8025db38(&local_148,(int *)&local_14c,&local_150,&local_154);
            if (local_14c < DAT_803dc02c) {
              iVar6 = 0;
            }
            else {
              iVar6 = local_14c - DAT_803dc02c;
            }
            FUN_8025da88(local_148,iVar6,local_150,local_154);
          }
          if (*(char *)((int)puVar10 + 0xe) == '\x05') {
            uVar7 = (uint)*(byte *)(puVar10 + 3) +
                    (int)*(char *)(puVar10 + 2) + (int)*(char *)((int)puVar10 + 9);
            uVar17 = (uint)*(byte *)((int)puVar10 + 0xd) +
                     (int)*(char *)((int)puVar10 + 10) + (int)*(char *)((int)puVar10 + 0xb);
            FUN_8025db38(&local_148,(int *)&local_14c,&local_150,&local_154);
            FUN_8005524c(0,0,(int)DAT_802c8b54,(int)DAT_802c8b56,
                         (int)DAT_802c8b54 + (uint)DAT_802c8b48,
                         (int)DAT_802c8b56 + (uint)DAT_802c8b4a);
            uVar8 = (int)DAT_802c8b54 + ((int)(DAT_802c8b48 - uVar7) >> 1) ^ 0x80000000;
            local_e8 = (double)CONCAT44(0x43300000,uVar8);
            local_f0 = (double)CONCAT44(0x43300000,uVar8);
            local_f8 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            uVar8 = (int)DAT_802c8b56 + ((int)(DAT_802c8b4a - uVar17) >> 1) ^ 0x80000000;
            local_100 = (double)CONCAT44(0x43300000,uVar8);
            local_108 = (double)CONCAT44(0x43300000,uVar8);
            local_110 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
            dVar29 = (double)((float)(local_e8 - DOUBLE_803df378) * FLOAT_803df390);
            dVar27 = (double)(((float)(local_f0 - DOUBLE_803df378) +
                              (float)(local_f8 - DOUBLE_803df378)) * FLOAT_803df390);
            dVar28 = (double)((float)(local_100 - DOUBLE_803df378) * FLOAT_803df390);
            dVar26 = (double)(((float)(local_108 - DOUBLE_803df378) +
                              (float)(local_110 - DOUBLE_803df378)) * FLOAT_803df390);
          }
          if (param_6 != 0) {
            local_e8 = (double)CONCAT44(0x43300000,DAT_803dd60c ^ 0x80000000);
            dVar29 = (double)(float)(dVar29 + (double)(float)(local_e8 - DOUBLE_803df378));
            local_f0 = (double)CONCAT44(0x43300000,DAT_803dd60c ^ 0x80000000);
            dVar27 = (double)(float)(dVar27 + (double)(float)(local_f0 - DOUBLE_803df378));
            local_f8 = (double)CONCAT44(0x43300000,DAT_803dd608 ^ 0x80000000);
            dVar28 = (double)(float)(dVar28 + (double)(float)(local_f8 - DOUBLE_803df378));
            local_100 = (double)CONCAT44(0x43300000,DAT_803dd608 ^ 0x80000000);
            dVar26 = (double)(float)(dVar26 + (double)(float)(local_100 - DOUBLE_803df378));
          }
          if ((DAT_803dd63c == 0) && (uVar8 = (uint)*(byte *)((int)puVar10 + 0xf), uVar12 != uVar8))
          {
            unaff_r28 = DAT_803dd66c[uVar8 + 4];
            FUN_8004c460(unaff_r28,0);
            uVar12 = uVar8;
            if ((&DAT_802c8e06)[(uint)*(byte *)((int)puVar10 + 0xe) * 0x10] == '\x01') {
              if (param_6 == 0) {
                FUN_8005d294(0,0xff,0xff,0xff,DAT_803dd624);
                FUN_80079b3c();
                FUN_80079764();
                FUN_80079980();
              }
              else {
                FUN_8005d294(0,0,0,0,DAT_803dd624);
              }
            }
            else {
              FUN_8005d294(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
              FUN_8005d264(0,DAT_803dd627,DAT_803dd626,DAT_803dd625,DAT_803dd624);
              FUN_80079b3c();
              FUN_80079120();
              FUN_80079980();
            }
          }
          if ((((DAT_803dd61c != 0) && (param_6 == 0)) && (*(char *)((int)puVar10 + 0xe) != '\x05'))
             && (local_e8 = (double)CONCAT44(0x43300000,DAT_803dd618 ^ 0x80000000),
                FLOAT_803dd614 <= (float)(local_e8 - DOUBLE_803df378))) {
            FUN_8005d294(0,0,0,0,0);
          }
          if (DAT_803dd5ec == (code *)0x0) {
            uStack_dc = (uint)*(ushort *)(unaff_r28 + 0xc);
            local_e0 = 0x43300000;
            dVar18 = (double)(FLOAT_803df398 *
                             (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803df370));
            local_e8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(unaff_r28 + 10));
            dVar20 = (double)(FLOAT_803df398 * (float)(local_e8 - DOUBLE_803df370));
            local_f0 = (double)(longlong)(int)dVar29;
            local_f8 = (double)(longlong)(int)dVar28;
            local_100 = (double)(longlong)(int)dVar27;
            local_108 = (double)(longlong)(int)dVar26;
            local_110 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar10 + 3) << 5 ^ 0x80000000);
            local_118 = (double)CONCAT44(0x43300000,
                                         (uint)*(byte *)((int)puVar10 + 0xd) << 5 ^ 0x80000000);
            FUN_80076008((double)(float)(dVar25 / dVar20),(double)(float)(dVar24 / dVar18),
                         (double)(float)((double)(float)(dVar25 + (double)(float)(local_110 -
                                                                                 DOUBLE_803df378)) /
                                        dVar20),
                         (double)(float)((double)(float)(dVar24 + (double)(float)(local_118 -
                                                                                 DOUBLE_803df378)) /
                                        dVar18),(int)dVar29,(int)dVar28,(short)(int)dVar27,
                         (short)(int)dVar26);
          }
          else {
            local_e8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(unaff_r28 + 0xc));
            dVar18 = (double)(FLOAT_803df398 * (float)(local_e8 - DOUBLE_803df370));
            local_f0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(unaff_r28 + 10));
            dVar20 = (double)(FLOAT_803df398 * (float)(local_f0 - DOUBLE_803df370));
            local_f8 = (double)(longlong)(int)dVar29;
            local_100 = (double)(longlong)(int)dVar28;
            local_108 = (double)(longlong)(int)dVar27;
            local_110 = (double)(longlong)(int)dVar26;
            local_118 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar10 + 3) << 5 ^ 0x80000000);
            uStack_dc = (uint)*(byte *)((int)puVar10 + 0xd) << 5 ^ 0x80000000;
            local_e0 = 0x43300000;
            (*DAT_803dd5ec)((double)(float)(dVar25 / dVar20),(double)(float)(dVar24 / dVar18),
                            (double)(float)((double)(float)(dVar25 + (double)(float)(local_118 -
                                                                                    DOUBLE_803df378)
                                                           ) / dVar20),
                            (double)(float)((double)(float)(dVar24 + (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack_dc) - DOUBLE_803df378))
                                           / dVar18),(int)dVar29,(int)dVar28,(int)dVar27,(int)dVar26
                           );
          }
          if ((*(char *)((int)puVar10 + 0xe) == '\x03') || (*(char *)((int)puVar10 + 0xe) == '\x05')
             ) {
            FUN_8025da88(local_148,local_14c,local_150,local_154);
          }
        }
        else {
          local_f0 = (double)CONCAT44(0x43300000,DAT_803dd630 ^ 0x80000000);
          if (dVar29 < (double)(float)(local_f0 - DOUBLE_803df378)) {
            DAT_803dd630 = (uint)dVar29;
            local_f8 = (double)(longlong)(int)DAT_803dd630;
          }
          local_100 = (double)CONCAT44(0x43300000,DAT_803dd62c ^ 0x80000000);
          if ((double)(float)(local_100 - DOUBLE_803df378) < dVar27) {
            DAT_803dd62c = (uint)dVar20;
            local_108 = (double)(longlong)(int)DAT_803dd62c;
          }
          local_110 = (double)CONCAT44(0x43300000,DAT_803dd638 ^ 0x80000000);
          if (dVar28 < (double)(float)(local_110 - DOUBLE_803df378)) {
            DAT_803dd638 = (uint)dVar28;
            local_118 = (double)(longlong)(int)DAT_803dd638;
          }
          local_e8 = (double)CONCAT44(0x43300000,DAT_803dd634 ^ 0x80000000);
          if ((double)(float)(local_e8 - DOUBLE_803df378) < dVar26) {
            DAT_803dd634 = (uint)dVar18;
            local_e8 = (double)(longlong)(int)DAT_803dd634;
          }
        }
        if (*(char *)((int)puVar10 + 0xe) != '\x05') {
          uStack_dc = (uint)*(byte *)(puVar10 + 3) +
                      (int)*(char *)(puVar10 + 2) + (int)*(char *)((int)puVar10 + 9) ^ 0x80000000;
          local_e0 = 0x43300000;
          dVar21 = (double)(float)((double)FLOAT_803dd620 *
                                   (double)(float)((double)CONCAT44(0x43300000,uStack_dc) -
                                                  DOUBLE_803df378) + dVar21);
        }
      }
    }
  }
  goto LAB_8001848c;
}

