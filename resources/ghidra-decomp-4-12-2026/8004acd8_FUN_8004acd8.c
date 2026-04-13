// Function: FUN_8004acd8
// Entry: 8004acd8
// Size: 1092 bytes

void FUN_8004acd8(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4,int param_5)

{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint *puVar9;
  uint uVar10;
  uint unaff_r29;
  int *piVar11;
  int iVar12;
  int unaff_r31;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286834();
  piVar4 = (int *)((ulonglong)uVar14 >> 0x20);
  uVar5 = FUN_8004aba0(piVar4,(int *)uVar14);
  if (uVar5 != 0) {
    sVar1 = *(short *)(piVar4 + 8);
    if (sVar1 != 0xfe) {
      *(short *)(piVar4 + 8) = sVar1 + 1;
      piVar11 = (int *)(*piVar4 + sVar1 * 0x10);
      *piVar11 = param_5;
      piVar11[2] = param_4;
      *(undefined *)(piVar11 + 3) = param_3;
      dVar13 = FUN_80021794((float *)(*piVar11 + 8),(float *)piVar4[3]);
      iVar6 = FUN_80286718(dVar13);
      piVar11[1] = iVar6;
    }
    puVar8 = (undefined4 *)piVar4[1];
    sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
    *(short *)((int)piVar4 + 0x22) = sVar3;
    *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
    puVar8[*(short *)((int)piVar4 + 0x22) * 2] = 0xfffffffe;
    iVar6 = (int)*(short *)((int)piVar4 + 0x22);
    uVar5 = puVar8[iVar6 * 2];
    uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
    *puVar8 = 0xffffffff;
    while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
      *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
      puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
      iVar6 = iVar7;
    }
    puVar8[iVar6 * 2] = uVar5;
    *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
  }
  uVar5 = 0;
  iVar7 = 0;
  sVar1 = *(short *)(piVar4 + 8);
  iVar12 = (int)sVar1;
  iVar6 = iVar12;
  if (0 < iVar12) {
    do {
      if (*(int *)(*piVar4 + iVar7) == param_5) {
        unaff_r29 = (uint)*(byte *)(*piVar4 + iVar7 + 0xe);
        goto LAB_8004ae34;
      }
      iVar7 = iVar7 + 0x10;
      uVar5 = uVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  uVar5 = 0xffffffff;
LAB_8004ae34:
  if (((int)uVar5 < 0) || (unaff_r29 != 0)) {
    if ((int)uVar5 < 0) {
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
        dVar13 = FUN_80021794((float *)(*piVar11 + 8),(float *)piVar4[3]);
        iVar6 = FUN_80286718(dVar13);
        piVar11[1] = iVar6;
      }
      if (piVar11 != (int *)0x0) {
        uVar5 = piVar11[1];
        if ((uint)piVar4[9] < uVar5) {
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (uVar5 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
        else {
          if (uVar5 < (uint)piVar4[9]) {
            piVar4[9] = uVar5;
          }
          iVar7 = piVar11[1];
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (iVar7 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
      }
    }
  }
  else {
    iVar6 = *piVar4 + uVar5 * 0x10;
    if (param_4 < *(uint *)(iVar6 + 8)) {
      *(undefined *)(iVar6 + 0xc) = param_3;
      *(uint *)(iVar6 + 8) = param_4;
      uVar10 = *(int *)(iVar6 + 4) + *(int *)(iVar6 + 8);
      iVar6 = (int)*(short *)((int)piVar4 + 0x22);
      puVar8 = (undefined4 *)piVar4[1];
      iVar7 = 0;
      while (iVar7 <= iVar6) {
        iVar12 = iVar7;
        if ((uVar5 & 0xffff) == (uint)*(ushort *)(puVar8 + iVar7 * 2 + 1)) {
          iVar12 = iVar6 + 1;
          unaff_r31 = iVar7;
        }
        iVar7 = iVar12 + 1;
      }
      puVar9 = puVar8 + unaff_r31 * 2;
      uVar5 = *puVar9;
      *puVar9 = uVar10;
      if (uVar10 < uVar5) {
        FUN_8004ac50((int)puVar8,iVar6,unaff_r31);
      }
      else if (uVar5 < uVar10) {
        uVar5 = *puVar9;
        uVar2 = *(undefined2 *)(puVar9 + 1);
        *puVar8 = 0xffffffff;
        while (iVar6 = unaff_r31 >> 1, (uint)puVar8[iVar6 * 2] < uVar5) {
          *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          puVar8[unaff_r31 * 2] = puVar8[iVar6 * 2];
          unaff_r31 = iVar6;
        }
        puVar8[unaff_r31 * 2] = uVar5;
        *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = uVar2;
      }
    }
  }
  FUN_80286880();
  return;
}

