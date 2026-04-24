// Function: FUN_80010ff4
// Entry: 80010ff4
// Size: 2296 bytes

void FUN_80010ff4(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4,
                 short *param_5)

{
  short sVar1;
  undefined2 uVar2;
  ushort uVar3;
  short sVar4;
  ushort uVar5;
  short sVar6;
  int *piVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  undefined2 *puVar13;
  uint uVar14;
  ushort *puVar15;
  int iVar16;
  int iVar17;
  int unaff_r14;
  short sVar18;
  int iVar19;
  int unaff_r21;
  int iVar20;
  uint uVar21;
  int unaff_r25;
  byte *pbVar22;
  double dVar23;
  byte local_78 [7];
  byte local_71;
  double local_68;
  double local_60;
  uint local_58;
  
  piVar7 = (int *)FUN_802860a8();
  sVar18 = (short)param_4;
  if ((*param_5 == *(short *)(piVar7 + 3)) && (param_5[2] == *(short *)(piVar7 + 4))) {
    sVar1 = *(short *)(piVar7 + 7);
    if (sVar1 == 200) {
      FUN_801378a8(s_VOXMAPS__route_nodes_list_overfl_802c6160);
    }
    else {
      *(short *)(piVar7 + 7) = sVar1 + 1;
      psVar9 = (short *)(*piVar7 + sVar1 * 0xe);
      *psVar9 = *param_5;
      psVar9[1] = param_5[1];
      psVar9[2] = param_5[2];
      psVar9[4] = sVar18;
      *(undefined *)(psVar9 + 5) = param_3;
      local_68 = (double)CONCAT44(0x43300000,
                                  ((int)*psVar9 - (int)*(short *)(piVar7 + 3)) *
                                  ((int)*psVar9 - (int)*(short *)(piVar7 + 3)) +
                                  ((int)psVar9[2] - (int)*(short *)(piVar7 + 4)) *
                                  ((int)psVar9[2] - (int)*(short *)(piVar7 + 4)) ^ 0x80000000);
      dVar23 = (double)FUN_802931a0((double)(float)(local_68 - DOUBLE_803de6a8));
      local_60 = (double)(longlong)(int)((double)FLOAT_803de6a0 * dVar23);
      psVar9[3] = (short)(int)((double)FLOAT_803de6a0 * dVar23);
    }
    puVar13 = (undefined2 *)piVar7[1];
    sVar4 = *(short *)((int)piVar7 + 0x1e) + 1;
    *(short *)((int)piVar7 + 0x1e) = sVar4;
    puVar13[sVar4 * 2 + 1] = sVar1;
    puVar13[*(short *)((int)piVar7 + 0x1e) * 2] = 0xfffe;
    iVar17 = (int)*(short *)((int)piVar7 + 0x1e);
    uVar5 = puVar13[iVar17 * 2];
    uVar2 = puVar13[iVar17 * 2 + 1];
    *puVar13 = 0xffff;
    while (iVar10 = iVar17 >> 1, (ushort)puVar13[iVar10 * 2] <= uVar5) {
      (puVar13 + iVar17 * 2)[1] = (puVar13 + iVar10 * 2)[1];
      puVar13[iVar17 * 2] = puVar13[iVar10 * 2];
      iVar17 = iVar10;
    }
    puVar13[iVar17 * 2] = uVar5;
    puVar13[iVar17 * 2 + 1] = uVar2;
  }
  uVar11 = *param_5 - DAT_803387f0;
  uVar14 = param_5[2] - DAT_803387f4;
  if (((int)uVar11 >> 6 != 0) || ((int)uVar14 >> 6 != 0)) {
    FUN_80012fb8(param_5);
    uVar11 = *param_5 - DAT_803387f0;
    uVar14 = param_5[2] - DAT_803387f4;
  }
  iVar17 = DAT_803387f8;
  if (DAT_803387f8 != 0) {
    uVar21 = (int)(uVar11 & 0x3f) >> 2;
    iVar20 = (int)(uVar14 & 0x3f) >> 2;
    iVar10 = (uVar11 & 3) * 2;
    iVar19 = 0;
    pbVar22 = local_78;
    do {
      iVar16 = iVar19 + param_5[1] + -1;
      iVar8 = *(int *)(iVar17 + 4);
      if (iVar16 < iVar8) {
        iVar8 = 0;
      }
      else if (iVar16 < *(int *)(iVar17 + 0xc)) {
        iVar8 = iVar16 - iVar8;
      }
      else {
        iVar8 = (*(int *)(iVar17 + 0xc) + -1) - iVar8;
      }
      if (((int)(uint)*(byte *)(*(int *)(iVar17 + 0x24) +
                               (iVar8 << 5 | iVar20 * 2 + ((int)(uVar11 & 0x3f) >> 5))) >>
           (uVar21 & 7) & 1U) == 0) {
        *pbVar22 = 0;
        pbVar22[1] = 0;
        pbVar22[2] = 0;
        pbVar22[3] = 0;
      }
      else {
        iVar8 = FUN_80012ec0(*(undefined4 *)(iVar17 + 0x1c),*(undefined4 *)(iVar17 + 0x14),
                             *(int *)(iVar17 + 0x24),uVar21,iVar8,iVar20);
        uVar12 = (uint)*(byte *)((uVar14 & 3) + iVar8);
        *pbVar22 = (byte)((int)uVar12 >> iVar10) & 3;
        pbVar22[1] = (byte)((int)uVar12 >> iVar10 + 2) & 3;
        uVar12 = (uint)*(byte *)((uVar14 & 3) + 1 + iVar8);
        pbVar22[2] = (byte)((int)uVar12 >> iVar10) & 3;
        pbVar22[3] = (byte)((int)uVar12 >> iVar10 + 2) & 3;
      }
      pbVar22 = pbVar22 + 4;
      iVar19 = iVar19 + 1;
    } while (iVar19 < 3);
    if (*(char *)((int)piVar7 + 0x26) == '\0') {
      iVar17 = 1;
    }
    else {
      if (((((local_78[4] & 2) != 0) || ((local_78[5] & 2) != 0)) || ((local_78[6] & 2) != 0)) ||
         ((local_71 & 2) != 0)) {
        unaff_r25 = 1;
      }
      iVar17 = -1;
    }
    while (-1 < iVar17) {
      iVar19 = iVar17 + 1;
      unaff_r25 = 0;
      iVar10 = iVar17 * 4;
      if ((((local_78[iVar10] & 2) != 0) || ((local_78[iVar10 + 1] & 2) != 0)) ||
         (((local_78[iVar10 + 2] & 2) != 0 || (iVar20 = iVar17, (local_78[iVar10 + 3] & 2) != 0))))
      {
        unaff_r25 = 1;
        iVar20 = 0;
      }
      if ((unaff_r25 == 0) &&
         (((iVar10 = iVar19 * 4, (local_78[iVar10] & 2) != 0 || ((local_78[iVar10 + 1] & 2) != 0))
          || (((local_78[iVar10 + 2] & 2) != 0 || ((local_78[iVar10 + 3] & 2) != 0)))))) {
        unaff_r25 = 1;
        iVar20 = 0;
      }
      unaff_r21 = iVar17;
      if (unaff_r25 == 0) {
        iVar10 = iVar20 * 4;
        iVar8 = iVar19 * 4;
        uVar14 = (uint)local_78[iVar10] + (uint)local_78[iVar10 + 1] + (uint)local_78[iVar10 + 2] +
                 (uint)local_78[iVar10 + 3];
        uVar11 = (uint)local_78[iVar8] + (uint)local_78[iVar8 + 1] + (uint)local_78[iVar8 + 2] +
                 (uint)local_78[iVar8 + 3];
        if ((iVar19 == 2) && (uVar11 == 0)) {
          unaff_r25 = 1;
        }
        else {
          if (iVar19 == 1) {
            if (uVar11 <= uVar14) {
              iVar17 = iVar17 + -1;
              uVar11 = uVar14;
            }
          }
          else if (uVar11 < uVar14) {
            iVar17 = iVar17 + -1;
            uVar11 = uVar14;
          }
          unaff_r21 = iVar17;
          if (uVar11 < 2) {
            unaff_r25 = 1;
          }
          else {
            iVar20 = 0;
          }
        }
      }
      iVar17 = iVar20 + -1;
    }
    if (unaff_r25 == 0) {
      param_5[1] = param_5[1] + (short)unaff_r21;
      uVar11 = 0;
      iVar10 = 0;
      sVar1 = *(short *)(piVar7 + 7);
      iVar19 = (int)sVar1;
      iVar17 = iVar19;
      if (0 < iVar19) {
        do {
          psVar9 = (short *)(*piVar7 + iVar10);
          if ((*psVar9 == *param_5) && (psVar9[2] == param_5[2])) {
            local_58 = (uint)*(byte *)(psVar9 + 6);
            goto LAB_8001155c;
          }
          iVar10 = iVar10 + 0xe;
          uVar11 = uVar11 + 1;
          iVar17 = iVar17 + -1;
        } while (iVar17 != 0);
      }
      uVar11 = 0xffffffff;
LAB_8001155c:
      if (((int)uVar11 < 0) || (local_58 != 0)) {
        if ((int)uVar11 < 0) {
          if (iVar19 == 200) {
            FUN_801378a8(s_VOXMAPS__route_nodes_list_overfl_802c6160);
            psVar9 = (short *)0x0;
          }
          else {
            sVar4 = *(short *)(piVar7 + 7);
            *(short *)(piVar7 + 7) = sVar4 + 1;
            psVar9 = (short *)(*piVar7 + sVar4 * 0xe);
            *psVar9 = *param_5;
            psVar9[1] = param_5[1];
            psVar9[2] = param_5[2];
            psVar9[4] = sVar18;
            *(undefined *)(psVar9 + 5) = param_3;
            local_60 = (double)CONCAT44(0x43300000,
                                        ((int)*psVar9 - (int)*(short *)(piVar7 + 3)) *
                                        ((int)*psVar9 - (int)*(short *)(piVar7 + 3)) +
                                        ((int)psVar9[2] - (int)*(short *)(piVar7 + 4)) *
                                        ((int)psVar9[2] - (int)*(short *)(piVar7 + 4)) ^ 0x80000000)
            ;
            dVar23 = (double)FUN_802931a0((double)(float)(local_60 - DOUBLE_803de6a8));
            local_68 = (double)(longlong)(int)((double)FLOAT_803de6a0 * dVar23);
            psVar9[3] = (short)(int)((double)FLOAT_803de6a0 * dVar23);
          }
          if (psVar9 == (short *)0x0) {
            FUN_801378a8(s_Childnode_Null_802c6184);
          }
          else {
            uVar5 = psVar9[3];
            if ((int)*(short *)(piVar7 + 9) < (int)(uint)uVar5) {
              sVar18 = psVar9[4];
              puVar13 = (undefined2 *)piVar7[1];
              sVar4 = *(short *)((int)piVar7 + 0x1e) + 1;
              *(short *)((int)piVar7 + 0x1e) = sVar4;
              puVar13[sVar4 * 2 + 1] = sVar1;
              puVar13[*(short *)((int)piVar7 + 0x1e) * 2] = -1 - (uVar5 + sVar18);
              iVar17 = (int)*(short *)((int)piVar7 + 0x1e);
              uVar5 = puVar13[iVar17 * 2];
              uVar2 = puVar13[iVar17 * 2 + 1];
              *puVar13 = 0xffff;
              while (iVar10 = iVar17 >> 1, (ushort)puVar13[iVar10 * 2] <= uVar5) {
                (puVar13 + iVar17 * 2)[1] = (puVar13 + iVar10 * 2)[1];
                puVar13[iVar17 * 2] = puVar13[iVar10 * 2];
                iVar17 = iVar10;
              }
              puVar13[iVar17 * 2] = uVar5;
              puVar13[iVar17 * 2 + 1] = uVar2;
            }
            else {
              if ((int)(uint)uVar5 < (int)*(short *)(piVar7 + 9)) {
                *(ushort *)(piVar7 + 9) = uVar5;
              }
              sVar18 = psVar9[3];
              sVar4 = psVar9[4];
              puVar13 = (undefined2 *)piVar7[1];
              sVar6 = *(short *)((int)piVar7 + 0x1e) + 1;
              *(short *)((int)piVar7 + 0x1e) = sVar6;
              puVar13[sVar6 * 2 + 1] = sVar1;
              puVar13[*(short *)((int)piVar7 + 0x1e) * 2] = -1 - (sVar18 + sVar4);
              iVar17 = (int)*(short *)((int)piVar7 + 0x1e);
              uVar5 = puVar13[iVar17 * 2];
              uVar2 = puVar13[iVar17 * 2 + 1];
              *puVar13 = 0xffff;
              while (iVar10 = iVar17 >> 1, (ushort)puVar13[iVar10 * 2] <= uVar5) {
                (puVar13 + iVar17 * 2)[1] = (puVar13 + iVar10 * 2)[1];
                puVar13[iVar17 * 2] = puVar13[iVar10 * 2];
                iVar17 = iVar10;
              }
              puVar13[iVar17 * 2] = uVar5;
              puVar13[iVar17 * 2 + 1] = uVar2;
            }
          }
        }
      }
      else {
        iVar17 = *piVar7 + uVar11 * 0xe;
        if ((param_4 & 0xffff) < (uint)*(ushort *)(iVar17 + 8)) {
          *(undefined *)(iVar17 + 10) = param_3;
          *(short *)(iVar17 + 8) = sVar18;
          uVar5 = *(short *)(iVar17 + 6) + *(short *)(iVar17 + 8);
          iVar17 = (int)*(short *)((int)piVar7 + 0x1e);
          puVar13 = (undefined2 *)piVar7[1];
          iVar10 = 0;
          while (iVar10 <= iVar17) {
            iVar19 = iVar10;
            if ((uVar11 & 0xffff) == (uint)(ushort)puVar13[iVar10 * 2 + 1]) {
              iVar19 = iVar17 + 1;
              unaff_r14 = iVar10;
            }
            iVar10 = iVar19 + 1;
          }
          puVar15 = puVar13 + unaff_r14 * 2;
          uVar3 = *puVar15;
          *puVar15 = uVar5;
          if (uVar5 < uVar3) {
            FUN_80010f6c(puVar13,iVar17,unaff_r14);
          }
          else if (uVar3 < uVar5) {
            uVar5 = *puVar15;
            uVar3 = puVar15[1];
            *puVar13 = 0xffff;
            while (iVar17 = unaff_r14 >> 1, (ushort)puVar13[iVar17 * 2] <= uVar5) {
              (puVar13 + unaff_r14 * 2)[1] = (puVar13 + iVar17 * 2)[1];
              puVar13[unaff_r14 * 2] = puVar13[iVar17 * 2];
              unaff_r14 = iVar17;
            }
            puVar13[unaff_r14 * 2] = uVar5;
            puVar13[unaff_r14 * 2 + 1] = uVar3;
          }
        }
      }
    }
  }
  FUN_802860f4();
  return;
}

