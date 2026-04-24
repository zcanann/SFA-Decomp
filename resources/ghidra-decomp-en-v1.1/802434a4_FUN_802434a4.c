// Function: FUN_802434a4
// Entry: 802434a4
// Size: 372 bytes

void FUN_802434a4(int param_1,int param_2)

{
  byte *pbVar1;
  uint uVar2;
  uint *puVar3;
  ushort *puVar4;
  undefined *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint unaff_r29;
  int iVar12;
  int iVar13;
  uint uVar14;
  
  puVar3 = (uint *)(param_1 + 0x10);
  iVar9 = 0;
  iVar12 = 0;
  iVar13 = *(int *)(param_1 + 4);
  iVar10 = *(int *)(param_1 + 8);
  iVar11 = *(int *)(param_1 + 0xc);
  do {
    if (iVar12 == 0) {
      unaff_r29 = *puVar3;
      iVar12 = 0x20;
      puVar3 = puVar3 + 1;
    }
    if ((unaff_r29 & 0x80000000) == 0) {
      puVar4 = (ushort *)(param_1 + iVar10);
      iVar10 = iVar10 + 2;
      iVar8 = iVar9 - ((*(byte *)puVar4 & 0xf) << 8 | (uint)*(byte *)((int)puVar4 + 1));
      if ((int)(uint)*puVar4 >> 0xc == 0) {
        pbVar1 = (byte *)(param_1 + iVar11);
        iVar11 = iVar11 + 1;
        uVar2 = *pbVar1 + 0x12;
      }
      else {
        uVar2 = ((int)(uint)*puVar4 >> 0xc) + 2;
      }
      puVar5 = (undefined *)(param_2 + iVar9);
      if (uVar2 != 0) {
        uVar14 = uVar2 >> 3;
        if (uVar14 != 0) {
          do {
            iVar9 = iVar9 + 8;
            *puVar5 = *(undefined *)(param_2 + iVar8 + -1);
            puVar5[1] = *(undefined *)(param_2 + iVar8);
            puVar5[2] = *(undefined *)(param_2 + iVar8 + 1);
            puVar5[3] = *(undefined *)(param_2 + iVar8 + 2);
            puVar5[4] = *(undefined *)(param_2 + iVar8 + 3);
            iVar6 = iVar8 + 5;
            puVar5[5] = *(undefined *)(param_2 + iVar8 + 4);
            iVar7 = iVar8 + 6;
            iVar8 = iVar8 + 8;
            puVar5[6] = *(undefined *)(param_2 + iVar6);
            puVar5[7] = *(undefined *)(param_2 + iVar7);
            puVar5 = puVar5 + 8;
            uVar14 = uVar14 - 1;
          } while (uVar14 != 0);
          uVar2 = uVar2 & 7;
          if (uVar2 == 0) goto LAB_802435f4;
        }
        do {
          iVar6 = iVar8 + -1;
          iVar9 = iVar9 + 1;
          iVar8 = iVar8 + 1;
          *puVar5 = *(undefined *)(param_2 + iVar6);
          puVar5 = puVar5 + 1;
          uVar2 = uVar2 - 1;
        } while (uVar2 != 0);
      }
    }
    else {
      *(undefined *)(param_2 + iVar9) = *(undefined *)(param_1 + iVar11);
      iVar11 = iVar11 + 1;
      iVar9 = iVar9 + 1;
    }
LAB_802435f4:
    unaff_r29 = unaff_r29 << 1;
    iVar12 = iVar12 + -1;
    if (iVar13 <= iVar9) {
      return;
    }
  } while( true );
}

