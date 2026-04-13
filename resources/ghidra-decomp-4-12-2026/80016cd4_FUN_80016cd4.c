// Function: FUN_80016cd4
// Entry: 80016cd4
// Size: 1836 bytes

/* WARNING: Removing unreachable block (ram,0x800173e0) */
/* WARNING: Removing unreachable block (ram,0x800173d8) */
/* WARNING: Removing unreachable block (ram,0x800173d0) */
/* WARNING: Removing unreachable block (ram,0x80016cf4) */
/* WARNING: Removing unreachable block (ram,0x80016cec) */
/* WARNING: Removing unreachable block (ram,0x80016ce4) */

void FUN_80016cd4(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5)

{
  float fVar1;
  undefined *puVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  uint uVar10;
  uint *puVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  undefined *puVar15;
  uint uVar16;
  int iVar17;
  uint *puVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  uint *puVar22;
  int iVar23;
  uint uVar24;
  double extraout_f1;
  double in_f29;
  double in_f30;
  double dVar25;
  double in_f31;
  double dVar26;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar27;
  uint local_118;
  uint local_114;
  uint local_110 [40];
  undefined4 local_70;
  uint uStack_6c;
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
  uVar27 = FUN_80286824();
  puVar15 = (undefined *)((ulonglong)uVar27 >> 0x20);
  iVar17 = 0;
  uVar16 = 0;
  bVar4 = false;
  dVar26 = (double)FLOAT_803df384;
  if (DAT_803dd668 == 2) {
    uVar5 = 6;
  }
  else {
    uVar5 = (uint)(byte)(&DAT_802c7b54)[DAT_803dd664 * 8];
  }
  iVar12 = uVar5 * 0x10 + -0x7fd37200;
  *(int *)uVar27 = 0;
  if (param_5 != (float *)0x0) {
    uStack_6c = (uint)*(ushort *)(&DAT_802c8e0a + uVar5 * 0x10);
    local_70 = 0x43300000;
    *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803df370) *
                      param_2);
  }
  if (puVar15 == (undefined *)0x0) goto LAB_800173d0;
  uVar6 = (uint)DAT_803dd62a;
  if ((uVar6 != 0) || (dVar25 = extraout_f1, DAT_803dd628 != 0)) {
    local_70 = 0x43300000;
    dVar25 = (double)(float)((double)CONCAT44(0x43300000,uVar6) - DOUBLE_803df370);
    uStack_6c = uVar6;
  }
  local_110[8] = 0;
  puVar22 = local_110 + 8;
  puVar18 = puVar22;
  iVar19 = 0;
  uVar6 = 0;
  while (uVar7 = FUN_80015cf0(puVar15 + uVar6,(int *)&local_114), uVar7 != 0) {
    uVar6 = uVar6 + local_114;
    if (uVar7 == 0x20) {
      bVar4 = true;
      uVar16 = uVar6;
    }
    if ((uVar7 < 0xe000) || (0xf8ff < uVar7)) {
      puVar11 = (uint *)*DAT_803dd66c;
      for (iVar23 = DAT_803dd66c[2]; iVar23 != 0; iVar23 = iVar23 + -1) {
        if ((*puVar11 == uVar7) && (*(byte *)((int)puVar11 + 0xe) == uVar5)) goto LAB_80017118;
        puVar11 = puVar11 + 4;
      }
      puVar11 = (uint *)0x0;
LAB_80017118:
      if (puVar11 != (uint *)0x0) {
        uStack_6c = (uint)*(byte *)(puVar11 + 3) +
                    (int)*(char *)(puVar11 + 2) + (int)*(char *)((int)puVar11 + 9) ^ 0x80000000;
        local_70 = 0x43300000;
        dVar26 = (double)(float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                                          DOUBLE_803df378) + dVar26);
        if (dVar25 <= dVar26) {
          if (!bVar4) {
            uVar16 = uVar6 - local_114;
          }
          iVar17 = iVar17 + 1;
          *(uint *)((int)local_110 + iVar19 + 0x24) = uVar16;
          if (((1 < iVar17) && (puVar18[1] == *puVar18)) || (0x1d < iVar17)) goto LAB_800173d0;
          dVar26 = (double)FLOAT_803df384;
          bVar4 = false;
          puVar18 = puVar18 + 1;
          iVar19 = iVar19 + 4;
          uVar6 = uVar16;
        }
      }
    }
    else {
      puVar11 = &DAT_802c8e70;
      iVar23 = 0x17;
      do {
        if (*puVar11 == uVar7) {
          uVar10 = puVar11[1];
          goto LAB_80016e6c;
        }
        if (puVar11[2] == uVar7) {
          uVar10 = puVar11[3];
          goto LAB_80016e6c;
        }
        puVar11 = puVar11 + 4;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      uVar10 = 0;
LAB_80016e6c:
      iVar23 = 0;
      if (0 < (int)uVar10) {
        if (8 < (int)uVar10) {
          puVar11 = local_110;
          uVar24 = uVar10 - 1 >> 3;
          if (0 < (int)(uVar10 - 8)) {
            do {
              *puVar11 = (uint)CONCAT11(puVar15[uVar6],puVar15[uVar6 + 1]);
              puVar11[1] = (uint)CONCAT11(puVar15[uVar6 + 2],puVar15[uVar6 + 3]);
              puVar11[2] = (uint)CONCAT11(puVar15[uVar6 + 4],puVar15[uVar6 + 5]);
              puVar11[3] = (uint)CONCAT11(puVar15[uVar6 + 6],puVar15[uVar6 + 7]);
              puVar11[4] = (uint)CONCAT11(puVar15[uVar6 + 8],puVar15[uVar6 + 9]);
              puVar11[5] = (uint)CONCAT11(puVar15[uVar6 + 10],puVar15[uVar6 + 0xb]);
              iVar20 = uVar6 + 0xe;
              puVar11[6] = (uint)CONCAT11(puVar15[uVar6 + 0xc],puVar15[uVar6 + 0xd]);
              iVar21 = uVar6 + 0xf;
              uVar6 = uVar6 + 0x10;
              puVar11[7] = (uint)CONCAT11(puVar15[iVar20],puVar15[iVar21]);
              puVar11 = puVar11 + 8;
              iVar23 = iVar23 + 8;
              uVar24 = uVar24 - 1;
            } while (uVar24 != 0);
          }
        }
        puVar11 = local_110 + iVar23;
        iVar20 = uVar10 - iVar23;
        if (iVar23 < (int)uVar10) {
          do {
            iVar23 = uVar6 + 1;
            puVar2 = puVar15 + uVar6;
            uVar6 = uVar6 + 2;
            *puVar11 = (uint)CONCAT11(*puVar2,puVar15[iVar23]);
            puVar11 = puVar11 + 1;
            iVar20 = iVar20 + -1;
          } while (iVar20 != 0);
        }
      }
      bVar3 = true;
      if (uVar7 == 0xf8f7) {
        iVar12 = local_110[0] * 0x10 + -0x7fd37200;
        uVar5 = local_110[0];
      }
      else if (((int)uVar7 < 0xf8f7) && (uVar7 == 0xf8f4)) {
        uStack_6c = local_110[0] ^ 0x80000000;
        local_70 = 0x43300000;
        param_2 = (double)((float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803df378) *
                          FLOAT_803df388);
      }
      else {
        bVar3 = false;
      }
      if ((bVar3) && (uVar5 != 5)) {
        uStack_6c = (uint)*(ushort *)(iVar12 + 10);
        local_70 = 0x43300000;
        fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803df370) *
                       param_2);
        if ((param_5 != (float *)0x0) && (*param_5 < fVar1)) {
          *param_5 = fVar1;
        }
      }
    }
  }
  iVar12 = iVar17 + 1;
  local_110[iVar17 + 9] = uVar6;
  *(int *)uVar27 = iVar12;
  if (uVar6 == 0) goto LAB_800173d0;
  local_114 = uVar6 + iVar12 * 5;
  if (param_5 == (float *)0x0) {
    puVar8 = (undefined4 *)FUN_80023d8c(local_114,0);
  }
  else {
    puVar8 = (undefined4 *)FUN_80022b30(DAT_803dbfd8,local_114);
  }
  if (puVar8 == (undefined4 *)0x0) goto LAB_800173d0;
  if (local_114 != 0) {
    uVar16 = local_114 >> 3;
    puVar9 = puVar8;
    uVar5 = local_114;
    if (uVar16 != 0) {
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
        uVar16 = uVar16 - 1;
      } while (uVar16 != 0);
      uVar5 = local_114 & 7;
      if (uVar5 == 0) goto LAB_800172a4;
    }
    do {
      *(undefined *)puVar9 = 0;
      uVar5 = uVar5 - 1;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    } while (uVar5 != 0);
  }
LAB_800172a4:
  *puVar8 = puVar8 + iVar12;
  iVar17 = 0;
  puVar9 = puVar8 + iVar12;
  for (uVar16 = 0; (int)uVar16 < (int)uVar6; uVar16 = uVar16 + 1) {
    *(undefined *)puVar9 = *puVar15;
    puVar13 = (undefined4 *)((int)puVar9 + 1);
    puVar14 = puVar9;
    if (uVar16 == puVar22[1]) {
      do {
        uVar5 = 6;
        do {
          iVar12 = FUN_80015cf0((byte *)((int)puVar14 - uVar5),(int *)&local_118);
          if (uVar5 == local_118) {
            iVar12 = FUN_80015c00(iVar12);
            if (iVar12 == 0) {
              *(undefined *)((int)puVar9 + 1) = *(undefined *)puVar9;
              *(undefined *)puVar9 = 0;
              puVar13 = (undefined4 *)((int)puVar9 + 2);
              puVar8[iVar17 + 1] = (undefined *)((int)puVar9 + 1);
              puVar22 = puVar22 + 1;
              iVar17 = iVar17 + 1;
              goto LAB_800173b4;
            }
            if (local_118 != 0) {
              uVar5 = local_118 >> 3;
              uVar7 = local_118;
              if (uVar5 == 0) goto LAB_80017360;
              do {
                *(undefined *)((int)puVar14 + -1) = 0;
                *(undefined *)((int)puVar14 + -2) = 0;
                *(undefined *)((int)puVar14 + -3) = 0;
                *(undefined *)(puVar14 + -1) = 0;
                *(undefined *)((int)puVar14 + -5) = 0;
                *(undefined *)((int)puVar14 + -6) = 0;
                *(undefined *)((int)puVar14 + -7) = 0;
                puVar14 = puVar14 + -2;
                *(undefined *)puVar14 = 0;
                uVar5 = uVar5 - 1;
              } while (uVar5 != 0);
              for (uVar7 = local_118 & 7; uVar7 != 0; uVar7 = uVar7 - 1) {
LAB_80017360:
                puVar14 = (undefined4 *)((int)puVar14 + -1);
                *(undefined *)puVar14 = 0;
              }
            }
            break;
          }
          uVar5 = uVar5 - 1;
        } while (0 < (int)uVar5);
      } while( true );
    }
LAB_800173b4:
    puVar15 = puVar15 + 1;
    puVar9 = puVar13;
  }
  *(undefined *)puVar9 = 0;
LAB_800173d0:
  FUN_80286870();
  return;
}

