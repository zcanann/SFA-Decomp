// Function: FUN_800122b4
// Entry: 800122b4
// Size: 1192 bytes

void FUN_800122b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  undefined2 uVar4;
  ushort uVar5;
  short sVar6;
  float *pfVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined2 *puVar11;
  int iVar12;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined uVar13;
  byte bVar14;
  short *psVar15;
  int iVar16;
  double extraout_f1;
  double extraout_f1_00;
  double dVar17;
  undefined8 extraout_f1_01;
  undefined8 uVar18;
  short local_38;
  short local_36;
  short local_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  uVar18 = FUN_8028683c();
  pfVar7 = (float *)((ulonglong)uVar18 >> 0x20);
  piVar9 = (int *)uVar18;
  uVar13 = 0;
  bVar14 = *(byte *)(pfVar7 + 9);
  dVar17 = extraout_f1;
  if (bVar14 == 0) {
    iVar8 = 0;
    *(undefined2 *)((int)piVar9 + 0x1e) = 0;
    *(undefined2 *)(piVar9 + 7) = 0;
    iVar10 = 0;
    iVar16 = 0x19;
    do {
      *(undefined2 *)(piVar9[1] + iVar8) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0xc) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 4) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x1a) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 8) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x28) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 0xc) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x36) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 0x10) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x44) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 0x14) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x52) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 0x18) = 0;
      *(undefined *)(*piVar9 + iVar10 + 0x60) = 0;
      *(undefined2 *)(piVar9[1] + iVar8 + 0x1c) = 0;
      iVar12 = *piVar9;
      *(undefined *)(iVar12 + iVar10 + 0x6e) = 0;
      iVar8 = iVar8 + 0x20;
      iVar10 = iVar10 + 0x70;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    FUN_80012d20(pfVar7,(short *)((int)piVar9 + 0x12));
    uVar18 = FUN_80012d20(pfVar7 + 3,(short *)(piVar9 + 3));
    *(ushort *)((int)piVar9 + 0x12) = *(ushort *)((int)piVar9 + 0x12) & 0xfffe;
    *(ushort *)((int)piVar9 + 0x16) = *(ushort *)((int)piVar9 + 0x16) & 0xfffe;
    *(ushort *)(piVar9 + 3) = *(ushort *)(piVar9 + 3) & 0xfffe;
    *(ushort *)(piVar9 + 4) = *(ushort *)(piVar9 + 4) & 0xfffe;
    psVar15 = &local_38;
    iVar8 = FUN_80011a1c(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)piVar9 + 0x12,piVar9 + 3,(undefined4 *)psVar15);
    if (iVar8 == 0) {
      *(undefined2 *)(piVar9 + 9) = 10000;
      sVar2 = *(short *)(piVar9 + 7);
      if (sVar2 == 200) {
        dVar17 = (double)FUN_80137c30(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7
                                      ,param_8,s_VOXMAPS__route_nodes_list_overfl_802c68e0,200,
                                      psVar15,iVar12,in_r7,in_r8,in_r9,in_r10);
        psVar15 = (short *)0x0;
      }
      else {
        *(short *)(piVar9 + 7) = sVar2 + 1;
        psVar15 = (short *)(*piVar9 + sVar2 * 0xe);
        *psVar15 = local_38;
        psVar15[1] = local_36;
        psVar15[2] = local_34;
        psVar15[4] = 0;
        *(undefined *)(psVar15 + 5) = 0xff;
        uStack_2c = ((int)*psVar15 - (int)*(short *)(piVar9 + 3)) *
                    ((int)*psVar15 - (int)*(short *)(piVar9 + 3)) +
                    ((int)psVar15[2] - (int)*(short *)(piVar9 + 4)) *
                    ((int)psVar15[2] - (int)*(short *)(piVar9 + 4)) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar17 = FUN_80293900((double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                             DOUBLE_803df328));
        local_28 = (longlong)(int)((double)FLOAT_803df320 * dVar17);
        psVar15[3] = (short)(int)((double)FLOAT_803df320 * dVar17);
      }
      sVar2 = psVar15[3];
      sVar3 = psVar15[4];
      puVar11 = (undefined2 *)piVar9[1];
      sVar6 = *(short *)((int)piVar9 + 0x1e) + 1;
      *(short *)((int)piVar9 + 0x1e) = sVar6;
      puVar11[sVar6 * 2 + 1] = *(short *)(piVar9 + 7) + -1;
      puVar11[*(short *)((int)piVar9 + 0x1e) * 2] = -1 - (sVar2 + sVar3);
      iVar8 = (int)*(short *)((int)piVar9 + 0x1e);
      uVar5 = puVar11[iVar8 * 2];
      uVar4 = puVar11[iVar8 * 2 + 1];
      *puVar11 = 0xffff;
      while (iVar10 = iVar8 >> 1, (ushort)puVar11[iVar10 * 2] <= uVar5) {
        (puVar11 + iVar8 * 2)[1] = (puVar11 + iVar10 * 2)[1];
        puVar11[iVar8 * 2] = puVar11[iVar10 * 2];
        iVar8 = iVar10;
      }
      puVar11[iVar8 * 2] = uVar5;
      puVar11[iVar8 * 2 + 1] = uVar4;
      bVar1 = false;
      *(undefined2 *)(piVar9 + 8) = 0;
    }
    else {
      bVar1 = true;
      dVar17 = extraout_f1_00;
    }
    if (bVar1) {
      pfVar7[6] = pfVar7[3];
      pfVar7[7] = pfVar7[4];
      pfVar7[8] = pfVar7[5];
      uVar13 = 1;
    }
    else {
      bVar14 = 1;
    }
  }
  if (bVar14 != 0) {
    iVar8 = FUN_8001275c(dVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (iVar8 == 0) {
      bVar1 = *(byte *)((int)pfVar7 + 0x26) <= bVar14;
      bVar14 = bVar14 + 1;
      if (bVar1) {
        bVar14 = 0;
        iVar8 = FUN_80011ed0(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,param_8)
        ;
        if (iVar8 == 0) {
          pfVar7[6] = pfVar7[3];
          pfVar7[7] = pfVar7[4];
          pfVar7[8] = pfVar7[5];
          uVar13 = 1;
        }
        else {
          pfVar7[6] = *(float *)piVar9[2];
          pfVar7[7] = *(float *)(piVar9[2] + 4);
          pfVar7[8] = *(float *)(piVar9[2] + 8);
        }
      }
    }
    else if (iVar8 < 0) {
      if (-2 < iVar8) {
        pfVar7[6] = *pfVar7;
        pfVar7[7] = pfVar7[1];
        pfVar7[8] = pfVar7[2];
        uVar13 = 1;
        bVar14 = 0;
      }
    }
    else if (iVar8 < 2) {
      bVar14 = 0;
      iVar8 = FUN_80011ed0(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (iVar8 == 0) {
        pfVar7[6] = pfVar7[3];
        pfVar7[7] = pfVar7[4];
        pfVar7[8] = pfVar7[5];
        uVar13 = 1;
      }
      else {
        pfVar7[6] = *(float *)piVar9[2];
        pfVar7[7] = *(float *)(piVar9[2] + 4);
        pfVar7[8] = *(float *)(piVar9[2] + 8);
      }
    }
  }
  *(byte *)(pfVar7 + 9) = bVar14;
  *(undefined *)((int)pfVar7 + 0x25) = uVar13;
  FUN_80286888();
  return;
}

