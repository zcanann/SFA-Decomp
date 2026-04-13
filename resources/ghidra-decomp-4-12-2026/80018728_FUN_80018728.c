// Function: FUN_80018728
// Entry: 80018728
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x80018bdc) */
/* WARNING: Removing unreachable block (ram,0x80018bd4) */
/* WARNING: Removing unreachable block (ram,0x80018740) */
/* WARNING: Removing unreachable block (ram,0x80018738) */

void FUN_80018728(undefined4 param_1,undefined4 param_2,undefined4 *param_3,float *param_4,
                 float *param_5,uint param_6)

{
  float fVar1;
  undefined *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  double extraout_f1;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  int local_78;
  uint local_74 [23];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar14 = FUN_80286838();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  iVar7 = 0;
  dVar13 = (double)FLOAT_803df384;
  if (iVar3 != 0) {
    if (param_6 == 0xffffffff) {
      if (DAT_803dd668 == 2) {
        param_6 = 6;
      }
      else {
        param_6 = (uint)(byte)(&DAT_802c7b54)[DAT_803dd664 * 8];
      }
    }
    dVar12 = extraout_f1;
    if (param_6 != 5) {
      if (param_4 != (float *)0x0) {
        local_74[10] = (uint)*(ushort *)(&DAT_802c8e08 + param_6 * 0x10);
        local_74[9] = 0x43300000;
        *param_4 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                          DOUBLE_803df370) * extraout_f1);
      }
      if (param_5 != (float *)0x0) {
        local_74[10] = (uint)*(ushort *)(&DAT_802c8e0a + param_6 * 0x10);
        local_74[9] = 0x43300000;
        *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                          DOUBLE_803df370) * extraout_f1);
      }
    }
    while (uVar4 = FUN_80015cf0((byte *)(iVar3 + iVar7),&local_78), uVar4 != 0) {
      iVar7 = iVar7 + local_78;
      if ((uVar4 < 0xe000) || (0xf8ff < uVar4)) {
        puVar6 = (uint *)*DAT_803dd66c;
        for (iVar10 = DAT_803dd66c[2]; iVar10 != 0; iVar10 = iVar10 + -1) {
          if ((*puVar6 == uVar4) && (*(byte *)((int)puVar6 + 0xe) == param_6)) goto LAB_80018b58;
          puVar6 = puVar6 + 4;
        }
        puVar6 = (uint *)0x0;
LAB_80018b58:
        if ((puVar6 != (uint *)0x0) && (param_6 != 5)) {
          local_74[10] = (uint)*(byte *)(puVar6 + 3) +
                         (int)*(char *)(puVar6 + 2) + (int)*(char *)((int)puVar6 + 9) ^ 0x80000000;
          local_74[9] = 0x43300000;
          dVar13 = (double)(float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,local_74[10]
                                                                            ) - DOUBLE_803df378) +
                                  dVar13);
        }
      }
      else {
        puVar6 = &DAT_802c8e70;
        iVar10 = 0x17;
        do {
          if (*puVar6 == uVar4) {
            uVar5 = puVar6[1];
            goto LAB_80018888;
          }
          if (puVar6[2] == uVar4) {
            uVar5 = puVar6[3];
            goto LAB_80018888;
          }
          puVar6 = puVar6 + 4;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
        uVar5 = 0;
LAB_80018888:
        iVar10 = 0;
        if (0 < (int)uVar5) {
          if (8 < (int)uVar5) {
            puVar6 = local_74;
            uVar11 = uVar5 - 1 >> 3;
            if (0 < (int)(uVar5 - 8)) {
              do {
                *puVar6 = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7),
                                         *(undefined *)(iVar3 + iVar7 + 1));
                puVar6[1] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 2),
                                           *(undefined *)(iVar3 + iVar7 + 3));
                puVar6[2] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 4),
                                           *(undefined *)(iVar3 + iVar7 + 5));
                puVar6[3] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 6),
                                           *(undefined *)(iVar3 + iVar7 + 7));
                puVar6[4] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 8),
                                           *(undefined *)(iVar3 + iVar7 + 9));
                puVar6[5] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 10),
                                           *(undefined *)(iVar3 + iVar7 + 0xb));
                iVar8 = iVar7 + 0xe;
                puVar6[6] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar7 + 0xc),
                                           *(undefined *)(iVar3 + iVar7 + 0xd));
                iVar9 = iVar7 + 0xf;
                iVar7 = iVar7 + 0x10;
                puVar6[7] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8),
                                           *(undefined *)(iVar3 + iVar9));
                puVar6 = puVar6 + 8;
                iVar10 = iVar10 + 8;
                uVar11 = uVar11 - 1;
              } while (uVar11 != 0);
            }
          }
          puVar6 = local_74 + iVar10;
          iVar8 = uVar5 - iVar10;
          if (iVar10 < (int)uVar5) {
            do {
              iVar10 = iVar7 + 1;
              puVar2 = (undefined *)(iVar3 + iVar7);
              iVar7 = iVar7 + 2;
              *puVar6 = (uint)CONCAT11(*puVar2,*(undefined *)(iVar3 + iVar10));
              puVar6 = puVar6 + 1;
              iVar8 = iVar8 + -1;
            } while (iVar8 != 0);
          }
        }
        if (uVar4 == 0xf8f7) {
          param_6 = local_74[0];
          if (local_74[0] != 5) {
            fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,
                                                             (uint)*(ushort *)
                                                                    (&DAT_802c8e08 +
                                                                    local_74[0] * 0x10)) -
                                           DOUBLE_803df370) * dVar12);
            if ((param_4 != (float *)0x0) && (*param_4 < fVar1)) {
              *param_4 = fVar1;
            }
            local_74[10] = (uint)*(ushort *)(&DAT_802c8e0a + local_74[0] * 0x10);
            local_74[9] = 0x43300000;
            fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                           DOUBLE_803df370) * dVar12);
            if ((param_5 != (float *)0x0) && (*param_5 < fVar1)) {
              *param_5 = fVar1;
            }
          }
        }
        else if (((int)uVar4 < 0xf8f7) && (uVar4 == 0xf8f4)) {
          local_74[10] = local_74[0] ^ 0x80000000;
          local_74[9] = 0x43300000;
          dVar12 = (double)((float)((double)CONCAT44(0x43300000,local_74[10]) - DOUBLE_803df378) *
                           FLOAT_803df388);
        }
      }
    }
    if ((float *)uVar14 != (float *)0x0) {
      *(float *)uVar14 = (float)dVar13;
    }
    if ((float *)param_3 != (float *)0x0) {
      *param_3 = FLOAT_803df384;
    }
  }
  FUN_80286884();
  return;
}

