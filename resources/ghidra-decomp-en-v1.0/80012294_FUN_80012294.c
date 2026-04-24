// Function: FUN_80012294
// Entry: 80012294
// Size: 1192 bytes

void FUN_80012294(void)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  undefined2 uVar4;
  ushort uVar5;
  short sVar6;
  undefined4 *puVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined2 *puVar11;
  undefined uVar12;
  undefined4 uVar13;
  byte bVar14;
  short *psVar15;
  int iVar16;
  double dVar17;
  undefined8 uVar18;
  short local_38;
  short local_36;
  short local_34;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  
  uVar18 = FUN_802860d8();
  puVar7 = (undefined4 *)((ulonglong)uVar18 >> 0x20);
  piVar9 = (int *)uVar18;
  uVar12 = 0;
  bVar14 = *(byte *)(puVar7 + 9);
  uVar13 = 0;
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
      *(undefined *)(*piVar9 + iVar10 + 0x6e) = 0;
      iVar8 = iVar8 + 0x20;
      iVar10 = iVar10 + 0x70;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    FUN_80012d00(puVar7,(int)piVar9 + 0x12);
    FUN_80012d00(puVar7 + 3,piVar9 + 3);
    *(ushort *)((int)piVar9 + 0x12) = *(ushort *)((int)piVar9 + 0x12) & 0xfffe;
    *(ushort *)((int)piVar9 + 0x16) = *(ushort *)((int)piVar9 + 0x16) & 0xfffe;
    *(ushort *)(piVar9 + 3) = *(ushort *)(piVar9 + 3) & 0xfffe;
    *(ushort *)(piVar9 + 4) = *(ushort *)(piVar9 + 4) & 0xfffe;
    iVar8 = FUN_800119fc((int)piVar9 + 0x12,piVar9 + 3,&local_38);
    if (iVar8 == 0) {
      *(undefined2 *)(piVar9 + 9) = 10000;
      sVar2 = *(short *)(piVar9 + 7);
      if (sVar2 == 200) {
        FUN_801378a8(s_VOXMAPS__route_nodes_list_overfl_802c6160);
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
        uStack44 = ((int)*psVar15 - (int)*(short *)(piVar9 + 3)) *
                   ((int)*psVar15 - (int)*(short *)(piVar9 + 3)) +
                   ((int)psVar15[2] - (int)*(short *)(piVar9 + 4)) *
                   ((int)psVar15[2] - (int)*(short *)(piVar9 + 4)) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar17 = (double)FUN_802931a0((double)(float)((double)CONCAT44(0x43300000,uStack44) -
                                                     DOUBLE_803de6a8));
        local_28 = (longlong)(int)((double)FLOAT_803de6a0 * dVar17);
        psVar15[3] = (short)(int)((double)FLOAT_803de6a0 * dVar17);
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
    }
    if (bVar1) {
      puVar7[6] = puVar7[3];
      puVar7[7] = puVar7[4];
      puVar7[8] = puVar7[5];
      uVar13 = 1;
      uVar12 = 1;
    }
    else {
      bVar14 = 1;
    }
  }
  if (bVar14 != 0) {
    uVar13 = 1;
    iVar8 = FUN_8001273c(piVar9,*(undefined *)((int)puVar7 + 0x27));
    if (iVar8 == 0) {
      bVar1 = *(byte *)((int)puVar7 + 0x26) <= bVar14;
      bVar14 = bVar14 + 1;
      if (bVar1) {
        bVar14 = 0;
        iVar8 = FUN_80011eb0(piVar9,1);
        if (iVar8 == 0) {
          puVar7[6] = puVar7[3];
          puVar7[7] = puVar7[4];
          puVar7[8] = puVar7[5];
          uVar12 = 1;
        }
        else {
          puVar7[6] = *(undefined4 *)piVar9[2];
          puVar7[7] = *(undefined4 *)(piVar9[2] + 4);
          puVar7[8] = *(undefined4 *)(piVar9[2] + 8);
        }
      }
      uVar13 = 1;
    }
    else if (iVar8 < 0) {
      if (-2 < iVar8) {
        bVar14 = 0;
        puVar7[6] = *puVar7;
        puVar7[7] = puVar7[1];
        puVar7[8] = puVar7[2];
        uVar12 = 1;
      }
    }
    else if (iVar8 < 2) {
      bVar14 = 0;
      iVar8 = FUN_80011eb0(piVar9,1);
      if (iVar8 == 0) {
        puVar7[6] = puVar7[3];
        puVar7[7] = puVar7[4];
        puVar7[8] = puVar7[5];
        uVar12 = 1;
      }
      else {
        puVar7[6] = *(undefined4 *)piVar9[2];
        puVar7[7] = *(undefined4 *)(piVar9[2] + 4);
        puVar7[8] = *(undefined4 *)(piVar9[2] + 8);
      }
      uVar13 = 1;
    }
  }
  *(byte *)(puVar7 + 9) = bVar14;
  *(undefined *)((int)puVar7 + 0x25) = uVar12;
  FUN_80286124(uVar13);
  return;
}

