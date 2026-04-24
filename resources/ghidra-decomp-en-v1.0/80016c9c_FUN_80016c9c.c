// Function: FUN_80016c9c
// Entry: 80016c9c
// Size: 1836 bytes

/* WARNING: Removing unreachable block (ram,0x800173a0) */
/* WARNING: Removing unreachable block (ram,0x80017398) */
/* WARNING: Removing unreachable block (ram,0x800173a8) */

void FUN_80016c9c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5)

{
  float fVar1;
  undefined *puVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  uint uVar10;
  uint *puVar11;
  uint *puVar12;
  int iVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  undefined *puVar16;
  uint uVar17;
  int iVar18;
  uint *puVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  uint *puVar23;
  int iVar24;
  uint uVar25;
  undefined4 uVar26;
  double extraout_f1;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar27;
  undefined8 in_f31;
  double dVar28;
  undefined8 uVar29;
  uint local_118;
  uint local_114;
  uint local_110 [40];
  undefined4 local_70;
  uint uStack108;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar26 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar29 = FUN_802860c0();
  puVar16 = (undefined *)((ulonglong)uVar29 >> 0x20);
  iVar18 = 0;
  uVar17 = 0;
  bVar4 = false;
  dVar28 = (double)FLOAT_803de704;
  if (DAT_803dc9e8 == 2) {
    uVar5 = 6;
  }
  else {
    uVar5 = (uint)(byte)(&DAT_802c73d4)[DAT_803dc9e4 * 8];
  }
  iVar13 = uVar5 * 0x10 + -0x7fd37980;
  *(int *)uVar29 = 0;
  if (param_5 != (float *)0x0) {
    uStack108 = (uint)(ushort)(&DAT_802c868a)[uVar5 * 8];
    local_70 = 0x43300000;
    *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803de6f0) *
                      param_2);
  }
  if (puVar16 == (undefined *)0x0) {
    puVar6 = (undefined4 *)0x0;
    goto LAB_80017398;
  }
  uVar7 = (uint)DAT_803dc9aa;
  if ((uVar7 != 0) || (dVar27 = extraout_f1, DAT_803dc9a8 != 0)) {
    local_70 = 0x43300000;
    dVar27 = (double)(float)((double)CONCAT44(0x43300000,uVar7) - DOUBLE_803de6f0);
    uStack108 = uVar7;
  }
  local_110[8] = 0;
  puVar23 = local_110 + 8;
  puVar19 = puVar23;
  iVar20 = 0;
  uVar7 = 0;
  while (uVar8 = FUN_80015cb8(puVar16 + uVar7,&local_114), uVar8 != 0) {
    uVar7 = uVar7 + local_114;
    if (uVar8 == 0x20) {
      bVar4 = true;
      uVar17 = uVar7;
    }
    if ((uVar8 < 0xe000) || (0xf8ff < uVar8)) {
      puVar11 = *DAT_803dc9ec;
      for (puVar12 = DAT_803dc9ec[2]; puVar12 != (uint *)0x0; puVar12 = (uint *)((int)puVar12 + -1))
      {
        if ((*puVar11 == uVar8) && (*(byte *)((int)puVar11 + 0xe) == uVar5)) goto LAB_800170e0;
        puVar11 = puVar11 + 4;
      }
      puVar11 = (uint *)0x0;
LAB_800170e0:
      if (puVar11 != (uint *)0x0) {
        uStack108 = (uint)*(byte *)(puVar11 + 3) +
                    (int)*(char *)(puVar11 + 2) + (int)*(char *)((int)puVar11 + 9) ^ 0x80000000;
        local_70 = 0x43300000;
        dVar28 = (double)(float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                                          DOUBLE_803de6f8) + dVar28);
        if (dVar27 <= dVar28) {
          if (!bVar4) {
            uVar17 = uVar7 - local_114;
          }
          iVar18 = iVar18 + 1;
          *(uint *)((int)local_110 + iVar20 + 0x24) = uVar17;
          if ((1 < iVar18) && (puVar19[1] == *puVar19)) {
            puVar6 = (undefined4 *)0x0;
            goto LAB_80017398;
          }
          if (0x1d < iVar18) {
            puVar6 = (undefined4 *)0x0;
            goto LAB_80017398;
          }
          dVar28 = (double)FLOAT_803de704;
          bVar4 = false;
          puVar19 = puVar19 + 1;
          iVar20 = iVar20 + 4;
          uVar7 = uVar17;
        }
      }
    }
    else {
      puVar11 = &DAT_802c86f0;
      iVar24 = 0x17;
      do {
        if (*puVar11 == uVar8) {
          uVar10 = puVar11[1];
          goto LAB_80016e34;
        }
        if (puVar11[2] == uVar8) {
          uVar10 = puVar11[3];
          goto LAB_80016e34;
        }
        puVar11 = puVar11 + 4;
        iVar24 = iVar24 + -1;
      } while (iVar24 != 0);
      uVar10 = 0;
LAB_80016e34:
      iVar24 = 0;
      if (0 < (int)uVar10) {
        if (8 < (int)uVar10) {
          puVar11 = local_110;
          uVar25 = uVar10 - 1 >> 3;
          if (0 < (int)(uVar10 - 8)) {
            do {
              *puVar11 = (uint)CONCAT11(puVar16[uVar7],puVar16[uVar7 + 1]);
              puVar11[1] = (uint)CONCAT11(puVar16[uVar7 + 2],puVar16[uVar7 + 3]);
              puVar11[2] = (uint)CONCAT11(puVar16[uVar7 + 4],puVar16[uVar7 + 5]);
              puVar11[3] = (uint)CONCAT11(puVar16[uVar7 + 6],puVar16[uVar7 + 7]);
              puVar11[4] = (uint)CONCAT11(puVar16[uVar7 + 8],puVar16[uVar7 + 9]);
              puVar11[5] = (uint)CONCAT11(puVar16[uVar7 + 10],puVar16[uVar7 + 0xb]);
              iVar21 = uVar7 + 0xe;
              puVar11[6] = (uint)CONCAT11(puVar16[uVar7 + 0xc],puVar16[uVar7 + 0xd]);
              iVar22 = uVar7 + 0xf;
              uVar7 = uVar7 + 0x10;
              puVar11[7] = (uint)CONCAT11(puVar16[iVar21],puVar16[iVar22]);
              puVar11 = puVar11 + 8;
              iVar24 = iVar24 + 8;
              uVar25 = uVar25 - 1;
            } while (uVar25 != 0);
          }
        }
        puVar11 = local_110 + iVar24;
        iVar21 = uVar10 - iVar24;
        if (iVar24 < (int)uVar10) {
          do {
            iVar24 = uVar7 + 1;
            puVar2 = puVar16 + uVar7;
            uVar7 = uVar7 + 2;
            *puVar11 = (uint)CONCAT11(*puVar2,puVar16[iVar24]);
            puVar11 = puVar11 + 1;
            iVar21 = iVar21 + -1;
          } while (iVar21 != 0);
        }
      }
      bVar3 = true;
      if (uVar8 == 0xf8f7) {
        iVar13 = local_110[0] * 0x10 + -0x7fd37980;
        uVar5 = local_110[0];
      }
      else if (((int)uVar8 < 0xf8f7) && (uVar8 == 0xf8f4)) {
        uStack108 = local_110[0] ^ 0x80000000;
        local_70 = 0x43300000;
        param_2 = (double)((float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803de6f8) *
                          FLOAT_803de708);
      }
      else {
        bVar3 = false;
      }
      if ((bVar3) && (uVar5 != 5)) {
        uStack108 = (uint)*(ushort *)(iVar13 + 10);
        local_70 = 0x43300000;
        fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803de6f0) *
                       param_2);
        if ((param_5 != (float *)0x0) && (*param_5 < fVar1)) {
          *param_5 = fVar1;
        }
      }
    }
  }
  iVar13 = iVar18 + 1;
  local_110[iVar18 + 9] = uVar7;
  *(int *)uVar29 = iVar13;
  if (uVar7 == 0) {
    puVar6 = (undefined4 *)0x0;
    goto LAB_80017398;
  }
  local_114 = uVar7 + iVar13 * 5;
  if (param_5 == (float *)0x0) {
    puVar6 = (undefined4 *)FUN_80023cc8(local_114,0,0);
  }
  else {
    puVar6 = (undefined4 *)FUN_80022a6c(DAT_803db378);
  }
  if (puVar6 == (undefined4 *)0x0) {
    puVar6 = (undefined4 *)0x0;
    goto LAB_80017398;
  }
  if (local_114 != 0) {
    uVar17 = local_114 >> 3;
    puVar9 = puVar6;
    uVar5 = local_114;
    if (uVar17 != 0) {
      do {
        *(undefined *)puVar9 = 0;
        *(undefined *)((int)puVar9 + 1) = 0;
        *(undefined *)((int)puVar9 + 2) = 0;
        *(undefined *)((int)puVar9 + 3) = 0;
        *(undefined *)(puVar9 + 1) = 0;
        *(undefined *)((int)puVar9 + 5) = 0;
        *(undefined *)((int)puVar9 + 6) = 0;
        *(undefined *)((int)puVar9 + 7) = 0;
        puVar9 = puVar9 + 2;
        uVar17 = uVar17 - 1;
      } while (uVar17 != 0);
      uVar5 = local_114 & 7;
      if (uVar5 == 0) goto LAB_8001726c;
    }
    do {
      *(undefined *)puVar9 = 0;
      uVar5 = uVar5 - 1;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    } while (uVar5 != 0);
  }
LAB_8001726c:
  *puVar6 = puVar6 + iVar13;
  iVar18 = 0;
  puVar9 = puVar6 + iVar13;
  for (uVar17 = 0; (int)uVar17 < (int)uVar7; uVar17 = uVar17 + 1) {
    *(undefined *)puVar9 = *puVar16;
    puVar14 = (undefined4 *)((int)puVar9 + 1);
    puVar15 = puVar9;
    if (uVar17 == puVar23[1]) {
      do {
        uVar5 = 6;
        do {
          FUN_80015cb8((int)puVar15 - uVar5,&local_118);
          if (uVar5 == local_118) {
            iVar13 = FUN_80015bc8();
            if (iVar13 == 0) {
              *(undefined *)((int)puVar9 + 1) = *(undefined *)puVar9;
              *(undefined *)puVar9 = 0;
              puVar14 = (undefined4 *)((int)puVar9 + 2);
              puVar6[iVar18 + 1] = (undefined *)((int)puVar9 + 1);
              puVar23 = puVar23 + 1;
              iVar18 = iVar18 + 1;
              goto LAB_8001737c;
            }
            if (local_118 != 0) {
              uVar5 = local_118 >> 3;
              uVar8 = local_118;
              if (uVar5 == 0) goto LAB_80017328;
              do {
                *(undefined *)((int)puVar15 + -1) = 0;
                *(undefined *)((int)puVar15 + -2) = 0;
                *(undefined *)((int)puVar15 + -3) = 0;
                *(undefined *)(puVar15 + -1) = 0;
                *(undefined *)((int)puVar15 + -5) = 0;
                *(undefined *)((int)puVar15 + -6) = 0;
                *(undefined *)((int)puVar15 + -7) = 0;
                puVar15 = puVar15 + -2;
                *(undefined *)puVar15 = 0;
                uVar5 = uVar5 - 1;
              } while (uVar5 != 0);
              for (uVar8 = local_118 & 7; uVar8 != 0; uVar8 = uVar8 - 1) {
LAB_80017328:
                puVar15 = (undefined4 *)((int)puVar15 + -1);
                *(undefined *)puVar15 = 0;
              }
            }
            break;
          }
          uVar5 = uVar5 - 1;
        } while (0 < (int)uVar5);
      } while( true );
    }
LAB_8001737c:
    puVar16 = puVar16 + 1;
    puVar9 = puVar14;
  }
  *(undefined *)puVar9 = 0;
LAB_80017398:
  __psq_l0(auStack8,uVar26);
  __psq_l1(auStack8,uVar26);
  __psq_l0(auStack24,uVar26);
  __psq_l1(auStack24,uVar26);
  __psq_l0(auStack40,uVar26);
  __psq_l1(auStack40,uVar26);
  FUN_8028610c(puVar6);
  return;
}

