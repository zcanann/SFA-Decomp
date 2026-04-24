// Function: FUN_800186f0
// Entry: 800186f0
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x80018b9c) */
/* WARNING: Removing unreachable block (ram,0x80018ba4) */

void FUN_800186f0(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,float *param_5
                 ,uint param_6)

{
  float fVar1;
  undefined *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  undefined4 uVar13;
  double extraout_f1;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  int local_78;
  uint local_74 [23];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar16 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar16 >> 0x20);
  iVar8 = 0;
  dVar15 = (double)FLOAT_803de704;
  if (iVar3 != 0) {
    if (param_6 == 0xffffffff) {
      if (DAT_803dc9e8 == 2) {
        param_6 = 6;
      }
      else {
        param_6 = (uint)(byte)(&DAT_802c73d4)[DAT_803dc9e4 * 8];
      }
    }
    dVar14 = extraout_f1;
    if (param_6 != 5) {
      if (param_4 != (float *)0x0) {
        local_74[10] = (uint)*(ushort *)(&DAT_802c8688 + param_6 * 0x10);
        local_74[9] = 0x43300000;
        *param_4 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                          DOUBLE_803de6f0) * extraout_f1);
      }
      if (param_5 != (float *)0x0) {
        local_74[10] = (uint)(ushort)(&DAT_802c868a)[param_6 * 8];
        local_74[9] = 0x43300000;
        *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                          DOUBLE_803de6f0) * extraout_f1);
      }
    }
    while (uVar4 = FUN_80015cb8(iVar3 + iVar8,&local_78), uVar4 != 0) {
      iVar8 = iVar8 + local_78;
      if ((uVar4 < 0xe000) || (0xf8ff < uVar4)) {
        puVar7 = *DAT_803dc9ec;
        for (puVar6 = DAT_803dc9ec[2]; puVar6 != (uint *)0x0; puVar6 = (uint *)((int)puVar6 + -1)) {
          if ((*puVar7 == uVar4) && (*(byte *)((int)puVar7 + 0xe) == param_6)) goto LAB_80018b20;
          puVar7 = puVar7 + 4;
        }
        puVar7 = (uint *)0x0;
LAB_80018b20:
        if ((puVar7 != (uint *)0x0) && (param_6 != 5)) {
          local_74[10] = (uint)*(byte *)(puVar7 + 3) +
                         (int)*(char *)(puVar7 + 2) + (int)*(char *)((int)puVar7 + 9) ^ 0x80000000;
          local_74[9] = 0x43300000;
          dVar15 = (double)(float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,local_74[10]
                                                                            ) - DOUBLE_803de6f8) +
                                  dVar15);
        }
      }
      else {
        puVar7 = &DAT_802c86f0;
        iVar11 = 0x17;
        do {
          if (*puVar7 == uVar4) {
            uVar5 = puVar7[1];
            goto LAB_80018850;
          }
          if (puVar7[2] == uVar4) {
            uVar5 = puVar7[3];
            goto LAB_80018850;
          }
          puVar7 = puVar7 + 4;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        uVar5 = 0;
LAB_80018850:
        iVar11 = 0;
        if (0 < (int)uVar5) {
          if (8 < (int)uVar5) {
            puVar7 = local_74;
            uVar12 = uVar5 - 1 >> 3;
            if (0 < (int)(uVar5 - 8)) {
              do {
                *puVar7 = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8),
                                         *(undefined *)(iVar3 + iVar8 + 1));
                puVar7[1] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 2),
                                           *(undefined *)(iVar3 + iVar8 + 3));
                puVar7[2] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 4),
                                           *(undefined *)(iVar3 + iVar8 + 5));
                puVar7[3] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 6),
                                           *(undefined *)(iVar3 + iVar8 + 7));
                puVar7[4] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 8),
                                           *(undefined *)(iVar3 + iVar8 + 9));
                puVar7[5] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 10),
                                           *(undefined *)(iVar3 + iVar8 + 0xb));
                iVar9 = iVar8 + 0xe;
                puVar7[6] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar8 + 0xc),
                                           *(undefined *)(iVar3 + iVar8 + 0xd));
                iVar10 = iVar8 + 0xf;
                iVar8 = iVar8 + 0x10;
                puVar7[7] = (uint)CONCAT11(*(undefined *)(iVar3 + iVar9),
                                           *(undefined *)(iVar3 + iVar10));
                puVar7 = puVar7 + 8;
                iVar11 = iVar11 + 8;
                uVar12 = uVar12 - 1;
              } while (uVar12 != 0);
            }
          }
          puVar7 = local_74 + iVar11;
          iVar9 = uVar5 - iVar11;
          if (iVar11 < (int)uVar5) {
            do {
              iVar11 = iVar8 + 1;
              puVar2 = (undefined *)(iVar3 + iVar8);
              iVar8 = iVar8 + 2;
              *puVar7 = (uint)CONCAT11(*puVar2,*(undefined *)(iVar3 + iVar11));
              puVar7 = puVar7 + 1;
              iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
          }
        }
        if (uVar4 == 0xf8f7) {
          param_6 = local_74[0];
          if (local_74[0] != 5) {
            fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,
                                                             (uint)*(ushort *)
                                                                    (&DAT_802c8688 +
                                                                    local_74[0] * 0x10)) -
                                           DOUBLE_803de6f0) * dVar14);
            if ((param_4 != (float *)0x0) && (*param_4 < fVar1)) {
              *param_4 = fVar1;
            }
            local_74[10] = (uint)(ushort)(&DAT_802c868a)[local_74[0] * 8];
            local_74[9] = 0x43300000;
            fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,local_74[10]) -
                                           DOUBLE_803de6f0) * dVar14);
            if ((param_5 != (float *)0x0) && (*param_5 < fVar1)) {
              *param_5 = fVar1;
            }
          }
        }
        else if (((int)uVar4 < 0xf8f7) && (uVar4 == 0xf8f4)) {
          local_74[10] = local_74[0] ^ 0x80000000;
          local_74[9] = 0x43300000;
          dVar14 = (double)((float)((double)CONCAT44(0x43300000,local_74[10]) - DOUBLE_803de6f8) *
                           FLOAT_803de708);
        }
      }
    }
    if ((float *)uVar16 != (float *)0x0) {
      *(float *)uVar16 = (float)dVar15;
    }
    if (param_3 != (float *)0x0) {
      *param_3 = FLOAT_803de704;
    }
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  FUN_80286120();
  return;
}

