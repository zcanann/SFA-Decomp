// Function: FUN_80011014
// Entry: 80011014
// Size: 2296 bytes

void FUN_80011014(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,uint param_12,
                 short *param_13,byte *param_14,undefined2 *param_15,undefined4 param_16)

{
  short sVar1;
  undefined2 uVar2;
  ushort uVar3;
  undefined uVar4;
  short sVar5;
  ushort uVar6;
  short sVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  short *psVar11;
  byte *pbVar12;
  uint uVar13;
  uint uVar14;
  int extraout_r4;
  undefined2 *puVar15;
  uint uVar16;
  ushort *puVar17;
  int iVar18;
  int iVar19;
  int unaff_r14;
  short sVar20;
  int iVar21;
  int unaff_r21;
  uint uVar22;
  int unaff_r25;
  byte *pbVar23;
  double extraout_f1;
  double dVar24;
  undefined8 uVar25;
  byte local_78 [7];
  byte local_71;
  undefined8 local_68;
  undefined8 local_60;
  uint local_58;
  
  uVar25 = FUN_8028680c();
  piVar8 = (int *)((ulonglong)uVar25 >> 0x20);
  sVar20 = (short)param_12;
  uVar4 = (undefined)param_11;
  dVar24 = extraout_f1;
  if ((*param_13 == *(short *)(piVar8 + 3)) && (param_13[2] == *(short *)(piVar8 + 4))) {
    sVar1 = *(short *)(piVar8 + 7);
    if (sVar1 == 200) {
      dVar24 = (double)FUN_80137c30(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                    param_8,s_VOXMAPS__route_nodes_list_overfl_802c68e0,(int)uVar25,
                                    param_11,param_12,param_13,param_14,param_15,param_16);
    }
    else {
      *(short *)(piVar8 + 7) = sVar1 + 1;
      psVar11 = (short *)(*piVar8 + sVar1 * 0xe);
      *psVar11 = *param_13;
      psVar11[1] = param_13[1];
      psVar11[2] = param_13[2];
      psVar11[4] = sVar20;
      *(undefined *)(psVar11 + 5) = uVar4;
      local_68 = (double)CONCAT44(0x43300000,
                                  ((int)*psVar11 - (int)*(short *)(piVar8 + 3)) *
                                  ((int)*psVar11 - (int)*(short *)(piVar8 + 3)) +
                                  ((int)psVar11[2] - (int)*(short *)(piVar8 + 4)) *
                                  ((int)psVar11[2] - (int)*(short *)(piVar8 + 4)) ^ 0x80000000);
      dVar24 = FUN_80293900((double)(float)(local_68 - DOUBLE_803df328));
      local_60 = (double)(longlong)(int)((double)FLOAT_803df320 * dVar24);
      psVar11[3] = (short)(int)((double)FLOAT_803df320 * dVar24);
    }
    puVar15 = (undefined2 *)piVar8[1];
    sVar5 = *(short *)((int)piVar8 + 0x1e) + 1;
    *(short *)((int)piVar8 + 0x1e) = sVar5;
    puVar15[sVar5 * 2 + 1] = sVar1;
    puVar15[*(short *)((int)piVar8 + 0x1e) * 2] = 0xfffe;
    param_14 = (byte *)(int)*(short *)((int)piVar8 + 0x1e);
    uVar6 = puVar15[(int)param_14 * 2];
    uVar2 = puVar15[(int)param_14 * 2 + 1];
    *puVar15 = 0xffff;
    while (pbVar12 = (byte *)((int)param_14 >> 1), (ushort)puVar15[(int)pbVar12 * 2] <= uVar6) {
      param_15 = puVar15 + (int)pbVar12 * 2;
      (puVar15 + (int)param_14 * 2)[1] = param_15[1];
      puVar15[(int)param_14 * 2] = *param_15;
      param_14 = pbVar12;
    }
    puVar15[(int)param_14 * 2] = uVar6;
    puVar15[(int)param_14 * 2 + 1] = uVar2;
  }
  uVar13 = *param_13 - DAT_80339450;
  uVar16 = param_13[2] - DAT_80339454;
  if (((int)uVar13 >> 6 != 0) || ((int)uVar16 >> 6 != 0)) {
    dVar24 = (double)FUN_80012fd8(dVar24,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    uVar13 = *param_13 - DAT_80339450;
    uVar16 = param_13[2] - DAT_80339454;
  }
  iVar10 = DAT_80339458;
  if (DAT_80339458 != 0) {
    uVar22 = (int)(uVar13 & 0x3f) >> 2;
    pbVar12 = (byte *)((int)(uVar16 & 0x3f) >> 2);
    iVar18 = (uVar13 & 3) * 2;
    iVar21 = 0;
    pbVar23 = local_78;
    do {
      iVar19 = iVar21 + param_13[1] + -1;
      iVar9 = *(int *)(iVar10 + 4);
      if (iVar19 < iVar9) {
        iVar9 = 0;
      }
      else if (iVar19 < *(int *)(iVar10 + 0xc)) {
        iVar9 = iVar19 - iVar9;
      }
      else {
        iVar9 = (*(int *)(iVar10 + 0xc) + -1) - iVar9;
      }
      if (((int)(uint)*(byte *)(*(int *)(iVar10 + 0x24) +
                               (iVar9 << 5 | (int)pbVar12 * 2 + ((int)(uVar13 & 0x3f) >> 5))) >>
           (uVar22 & 7) & 1U) == 0) {
        *pbVar23 = 0;
        pbVar23[1] = 0;
        pbVar23[2] = 0;
        pbVar23[3] = 0;
      }
      else {
        param_14 = pbVar12;
        iVar9 = FUN_80012ee0(*(int *)(iVar10 + 0x1c),*(int *)(iVar10 + 0x14),*(int *)(iVar10 + 0x24)
                             ,uVar22,iVar9,(int)pbVar12);
        uVar14 = (uint)*(byte *)((uVar16 & 3) + iVar9);
        *pbVar23 = (byte)((int)uVar14 >> iVar18) & 3;
        pbVar23[1] = (byte)((int)uVar14 >> iVar18 + 2) & 3;
        uVar14 = (uint)*(byte *)((uVar16 & 3) + 1 + iVar9);
        pbVar23[2] = (byte)((int)uVar14 >> iVar18) & 3;
        pbVar23[3] = (byte)((int)uVar14 >> iVar18 + 2) & 3;
      }
      pbVar23 = pbVar23 + 4;
      iVar21 = iVar21 + 1;
    } while (iVar21 < 3);
    if (*(char *)((int)piVar8 + 0x26) == '\0') {
      iVar10 = 1;
    }
    else {
      if (((((local_78[4] & 2) != 0) || ((local_78[5] & 2) != 0)) || ((local_78[6] & 2) != 0)) ||
         ((local_71 & 2) != 0)) {
        unaff_r25 = 1;
      }
      iVar10 = -1;
    }
    while (-1 < iVar10) {
      iVar21 = iVar10 + 1;
      unaff_r25 = 0;
      iVar18 = iVar10 * 4;
      if ((((local_78[iVar18] & 2) != 0) || ((local_78[iVar18 + 1] & 2) != 0)) ||
         (((local_78[iVar18 + 2] & 2) != 0 || (iVar9 = iVar10, (local_78[iVar18 + 3] & 2) != 0)))) {
        unaff_r25 = 1;
        iVar9 = 0;
      }
      if ((unaff_r25 == 0) &&
         (((iVar18 = iVar21 * 4, (local_78[iVar18] & 2) != 0 || ((local_78[iVar18 + 1] & 2) != 0))
          || (((local_78[iVar18 + 2] & 2) != 0 || ((local_78[iVar18 + 3] & 2) != 0)))))) {
        unaff_r25 = 1;
        iVar9 = 0;
      }
      unaff_r21 = iVar10;
      if (unaff_r25 == 0) {
        iVar18 = iVar9 * 4;
        iVar19 = iVar21 * 4;
        param_14 = local_78 + iVar19;
        uVar16 = (uint)local_78[iVar18] + (uint)local_78[iVar18 + 1] + (uint)local_78[iVar18 + 2] +
                 (uint)local_78[iVar18 + 3];
        uVar13 = (uint)*param_14 + (uint)local_78[iVar19 + 1] + (uint)local_78[iVar19 + 2] +
                 (uint)local_78[iVar19 + 3];
        if ((iVar21 == 2) && (uVar13 == 0)) {
          unaff_r25 = 1;
        }
        else {
          if (iVar21 == 1) {
            if (uVar13 <= uVar16) {
              iVar10 = iVar10 + -1;
              uVar13 = uVar16;
            }
          }
          else if (uVar13 < uVar16) {
            iVar10 = iVar10 + -1;
            uVar13 = uVar16;
          }
          unaff_r21 = iVar10;
          if (uVar13 < 2) {
            unaff_r25 = 1;
          }
          else {
            iVar9 = 0;
          }
        }
      }
      iVar10 = iVar9 + -1;
    }
    if (unaff_r25 == 0) {
      param_13[1] = param_13[1] + (short)unaff_r21;
      iVar18 = (int)param_13[2];
      uVar13 = 0;
      iVar21 = 0;
      sVar1 = *(short *)(piVar8 + 7);
      iVar9 = (int)sVar1;
      iVar10 = iVar9;
      if (0 < iVar9) {
        do {
          psVar11 = (short *)(*piVar8 + iVar21);
          if (((int)*psVar11 == (int)*param_13) && (psVar11[2] == iVar18)) {
            local_58 = (uint)*(byte *)(psVar11 + 6);
            goto LAB_8001157c;
          }
          iVar21 = iVar21 + 0xe;
          uVar13 = uVar13 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
      }
      uVar13 = 0xffffffff;
LAB_8001157c:
      if (((int)uVar13 < 0) || (local_58 != 0)) {
        if ((int)uVar13 < 0) {
          if (iVar9 == 200) {
            dVar24 = (double)FUN_80137c30(dVar24,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8,s_VOXMAPS__route_nodes_list_overfl_802c68e0,
                                          (int)*param_13,uVar13,iVar18,iVar21,param_14,param_15,
                                          param_16);
            psVar11 = (short *)0x0;
            iVar10 = extraout_r4;
          }
          else {
            sVar5 = *(short *)(piVar8 + 7);
            *(short *)(piVar8 + 7) = sVar5 + 1;
            psVar11 = (short *)(*piVar8 + sVar5 * 0xe);
            *psVar11 = *param_13;
            psVar11[1] = param_13[1];
            psVar11[2] = param_13[2];
            psVar11[4] = sVar20;
            *(undefined *)(psVar11 + 5) = uVar4;
            iVar10 = (int)*psVar11 - (int)*(short *)(piVar8 + 3);
            local_60 = (double)CONCAT44(0x43300000,
                                        iVar10 * iVar10 +
                                        ((int)psVar11[2] - (int)*(short *)(piVar8 + 4)) *
                                        ((int)psVar11[2] - (int)*(short *)(piVar8 + 4)) ^ 0x80000000
                                       );
            dVar24 = FUN_80293900((double)(float)(local_60 - DOUBLE_803df328));
            local_68 = (double)(longlong)(int)((double)FLOAT_803df320 * dVar24);
            psVar11[3] = (short)(int)((double)FLOAT_803df320 * dVar24);
          }
          if (psVar11 == (short *)0x0) {
            FUN_80137c30(dVar24,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         s_Childnode_Null_802c6904,iVar10,uVar13,iVar18,iVar21,param_14,param_15,
                         param_16);
          }
          else {
            uVar6 = psVar11[3];
            if ((int)*(short *)(piVar8 + 9) < (int)(uint)uVar6) {
              sVar20 = psVar11[4];
              puVar15 = (undefined2 *)piVar8[1];
              sVar5 = *(short *)((int)piVar8 + 0x1e) + 1;
              *(short *)((int)piVar8 + 0x1e) = sVar5;
              puVar15[sVar5 * 2 + 1] = sVar1;
              puVar15[*(short *)((int)piVar8 + 0x1e) * 2] = -1 - (uVar6 + sVar20);
              iVar10 = (int)*(short *)((int)piVar8 + 0x1e);
              uVar6 = puVar15[iVar10 * 2];
              uVar2 = puVar15[iVar10 * 2 + 1];
              *puVar15 = 0xffff;
              while (iVar18 = iVar10 >> 1, (ushort)puVar15[iVar18 * 2] <= uVar6) {
                (puVar15 + iVar10 * 2)[1] = (puVar15 + iVar18 * 2)[1];
                puVar15[iVar10 * 2] = puVar15[iVar18 * 2];
                iVar10 = iVar18;
              }
              puVar15[iVar10 * 2] = uVar6;
              puVar15[iVar10 * 2 + 1] = uVar2;
            }
            else {
              if ((int)(uint)uVar6 < (int)*(short *)(piVar8 + 9)) {
                *(ushort *)(piVar8 + 9) = uVar6;
              }
              sVar20 = psVar11[3];
              sVar5 = psVar11[4];
              puVar15 = (undefined2 *)piVar8[1];
              sVar7 = *(short *)((int)piVar8 + 0x1e) + 1;
              *(short *)((int)piVar8 + 0x1e) = sVar7;
              puVar15[sVar7 * 2 + 1] = sVar1;
              puVar15[*(short *)((int)piVar8 + 0x1e) * 2] = -1 - (sVar20 + sVar5);
              iVar10 = (int)*(short *)((int)piVar8 + 0x1e);
              uVar6 = puVar15[iVar10 * 2];
              uVar2 = puVar15[iVar10 * 2 + 1];
              *puVar15 = 0xffff;
              while (iVar18 = iVar10 >> 1, (ushort)puVar15[iVar18 * 2] <= uVar6) {
                (puVar15 + iVar10 * 2)[1] = (puVar15 + iVar18 * 2)[1];
                puVar15[iVar10 * 2] = puVar15[iVar18 * 2];
                iVar10 = iVar18;
              }
              puVar15[iVar10 * 2] = uVar6;
              puVar15[iVar10 * 2 + 1] = uVar2;
            }
          }
        }
      }
      else {
        iVar10 = *piVar8 + uVar13 * 0xe;
        if ((param_12 & 0xffff) < (uint)*(ushort *)(iVar10 + 8)) {
          *(undefined *)(iVar10 + 10) = uVar4;
          *(short *)(iVar10 + 8) = sVar20;
          uVar6 = *(short *)(iVar10 + 6) + *(short *)(iVar10 + 8);
          iVar10 = (int)*(short *)((int)piVar8 + 0x1e);
          puVar15 = (undefined2 *)piVar8[1];
          iVar18 = 0;
          while (iVar18 <= iVar10) {
            iVar21 = iVar18;
            if ((uVar13 & 0xffff) == (uint)(ushort)puVar15[iVar18 * 2 + 1]) {
              iVar21 = iVar10 + 1;
              unaff_r14 = iVar18;
            }
            iVar18 = iVar21 + 1;
          }
          puVar17 = puVar15 + unaff_r14 * 2;
          uVar3 = *puVar17;
          *puVar17 = uVar6;
          if (uVar6 < uVar3) {
            FUN_80010f8c((int)puVar15,iVar10,unaff_r14);
          }
          else if (uVar3 < uVar6) {
            uVar6 = *puVar17;
            uVar3 = puVar17[1];
            *puVar15 = 0xffff;
            while (iVar10 = unaff_r14 >> 1, (ushort)puVar15[iVar10 * 2] <= uVar6) {
              (puVar15 + unaff_r14 * 2)[1] = (puVar15 + iVar10 * 2)[1];
              puVar15[unaff_r14 * 2] = puVar15[iVar10 * 2];
              unaff_r14 = iVar10;
            }
            puVar15[unaff_r14 * 2] = uVar6;
            puVar15[unaff_r14 * 2 + 1] = uVar3;
          }
        }
      }
    }
  }
  FUN_80286858();
  return;
}

