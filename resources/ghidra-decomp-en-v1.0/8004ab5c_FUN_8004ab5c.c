// Function: FUN_8004ab5c
// Entry: 8004ab5c
// Size: 1092 bytes

void FUN_8004ab5c(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4,int param_5)

{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  uint unaff_r29;
  int *piVar11;
  int iVar12;
  int unaff_r31;
  
  piVar4 = (int *)FUN_802860d0();
  iVar5 = FUN_8004aa24();
  if (iVar5 != 0) {
    sVar1 = *(short *)(piVar4 + 8);
    if (sVar1 != 0xfe) {
      *(short *)(piVar4 + 8) = sVar1 + 1;
      piVar11 = (int *)(*piVar4 + sVar1 * 0x10);
      *piVar11 = param_5;
      piVar11[2] = param_4;
      *(undefined *)(piVar11 + 3) = param_3;
      FUN_800216d0(*piVar11 + 8,piVar4[3]);
      iVar5 = FUN_80285fb4();
      piVar11[1] = iVar5;
    }
    puVar7 = (undefined4 *)piVar4[1];
    sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
    *(short *)((int)piVar4 + 0x22) = sVar3;
    *(short *)(puVar7 + sVar3 * 2 + 1) = sVar1;
    puVar7[*(short *)((int)piVar4 + 0x22) * 2] = 0xfffffffe;
    iVar5 = (int)*(short *)((int)piVar4 + 0x22);
    uVar9 = puVar7[iVar5 * 2];
    uVar2 = *(undefined2 *)(puVar7 + iVar5 * 2 + 1);
    *puVar7 = 0xffffffff;
    while (iVar6 = iVar5 >> 1, (uint)puVar7[iVar6 * 2] < uVar9) {
      *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = *(undefined2 *)(puVar7 + iVar6 * 2 + 1);
      puVar7[iVar5 * 2] = puVar7[iVar6 * 2];
      iVar5 = iVar6;
    }
    puVar7[iVar5 * 2] = uVar9;
    *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = uVar2;
  }
  uVar9 = 0;
  iVar6 = 0;
  sVar1 = *(short *)(piVar4 + 8);
  iVar12 = (int)sVar1;
  iVar5 = iVar12;
  if (0 < iVar12) {
    do {
      if (*(int *)(*piVar4 + iVar6) == param_5) {
        unaff_r29 = (uint)*(byte *)((int)(int *)(*piVar4 + iVar6) + 0xe);
        goto LAB_8004acb8;
      }
      iVar6 = iVar6 + 0x10;
      uVar9 = uVar9 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  uVar9 = 0xffffffff;
LAB_8004acb8:
  if (((int)uVar9 < 0) || (unaff_r29 != 0)) {
    if ((int)uVar9 < 0) {
      if (iVar12 == 0xfe) {
        piVar11 = (int *)0x0;
      }
      else {
        sVar3 = *(short *)(piVar4 + 8);
        *(short *)(piVar4 + 8) = sVar3 + 1;
        piVar11 = (int *)(*piVar4 + sVar3 * 0x10);
        *piVar11 = param_5;
        piVar11[2] = param_4;
        *(undefined *)(piVar11 + 3) = param_3;
        FUN_800216d0(*piVar11 + 8,piVar4[3]);
        iVar5 = FUN_80285fb4();
        piVar11[1] = iVar5;
      }
      if (piVar11 != (int *)0x0) {
        uVar9 = piVar11[1];
        if ((uint)piVar4[9] < uVar9) {
          iVar5 = piVar11[2];
          puVar7 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar7 + sVar3 * 2 + 1) = sVar1;
          puVar7[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (uVar9 + iVar5);
          iVar5 = (int)*(short *)((int)piVar4 + 0x22);
          uVar9 = puVar7[iVar5 * 2];
          uVar2 = *(undefined2 *)(puVar7 + iVar5 * 2 + 1);
          *puVar7 = 0xffffffff;
          while (iVar6 = iVar5 >> 1, (uint)puVar7[iVar6 * 2] < uVar9) {
            *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = *(undefined2 *)(puVar7 + iVar6 * 2 + 1);
            puVar7[iVar5 * 2] = puVar7[iVar6 * 2];
            iVar5 = iVar6;
          }
          puVar7[iVar5 * 2] = uVar9;
          *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = uVar2;
        }
        else {
          if (uVar9 < (uint)piVar4[9]) {
            piVar4[9] = uVar9;
          }
          iVar6 = piVar11[1];
          iVar5 = piVar11[2];
          puVar7 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar7 + sVar3 * 2 + 1) = sVar1;
          puVar7[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (iVar6 + iVar5);
          iVar5 = (int)*(short *)((int)piVar4 + 0x22);
          uVar9 = puVar7[iVar5 * 2];
          uVar2 = *(undefined2 *)(puVar7 + iVar5 * 2 + 1);
          *puVar7 = 0xffffffff;
          while (iVar6 = iVar5 >> 1, (uint)puVar7[iVar6 * 2] < uVar9) {
            *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = *(undefined2 *)(puVar7 + iVar6 * 2 + 1);
            puVar7[iVar5 * 2] = puVar7[iVar6 * 2];
            iVar5 = iVar6;
          }
          puVar7[iVar5 * 2] = uVar9;
          *(undefined2 *)(puVar7 + iVar5 * 2 + 1) = uVar2;
        }
      }
    }
  }
  else {
    iVar5 = *piVar4 + uVar9 * 0x10;
    if (param_4 < *(uint *)(iVar5 + 8)) {
      *(undefined *)(iVar5 + 0xc) = param_3;
      *(uint *)(iVar5 + 8) = param_4;
      uVar10 = *(int *)(iVar5 + 4) + *(int *)(iVar5 + 8);
      iVar5 = (int)*(short *)((int)piVar4 + 0x22);
      puVar7 = (undefined4 *)piVar4[1];
      iVar6 = 0;
      while (iVar6 <= iVar5) {
        iVar12 = iVar6;
        if ((uVar9 & 0xffff) == (uint)*(ushort *)(puVar7 + iVar6 * 2 + 1)) {
          iVar12 = iVar5 + 1;
          unaff_r31 = iVar6;
        }
        iVar6 = iVar12 + 1;
      }
      puVar8 = puVar7 + unaff_r31 * 2;
      uVar9 = *puVar8;
      *puVar8 = uVar10;
      if (uVar10 < uVar9) {
        FUN_8004aad4(puVar7,iVar5,unaff_r31);
      }
      else if (uVar9 < uVar10) {
        uVar9 = *puVar8;
        uVar2 = *(undefined2 *)(puVar8 + 1);
        *puVar7 = 0xffffffff;
        while (iVar5 = unaff_r31 >> 1, (uint)puVar7[iVar5 * 2] < uVar9) {
          *(undefined2 *)(puVar7 + unaff_r31 * 2 + 1) = *(undefined2 *)(puVar7 + iVar5 * 2 + 1);
          puVar7[unaff_r31 * 2] = puVar7[iVar5 * 2];
          unaff_r31 = iVar5;
        }
        puVar7[unaff_r31 * 2] = uVar9;
        *(undefined2 *)(puVar7 + unaff_r31 * 2 + 1) = uVar2;
      }
    }
  }
  FUN_8028611c();
  return;
}

