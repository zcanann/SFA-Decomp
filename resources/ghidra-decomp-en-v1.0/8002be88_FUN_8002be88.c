// Function: FUN_8002be88
// Entry: 8002be88
// Size: 1252 bytes

void FUN_8002be88(void)

{
  char cVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  code *pcVar10;
  int iVar11;
  undefined8 uVar12;
  int local_b8 [46];
  
  uVar12 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar4 = (int)uVar12;
  if (*(char *)(iVar3 + 0xe9) != '\0') {
    FUN_80037e44();
  }
  sVar2 = *(short *)(iVar3 + 0x46);
  if ((sVar2 == 0x1f) || ((sVar2 < 0x1f && (sVar2 == 0)))) {
    FUN_802b4de0(iVar3,iVar4);
  }
  else if (*(int **)(iVar3 + 0x68) != (int *)0x0) {
    pcVar10 = *(code **)(**(int **)(iVar3 + 0x68) + 0x14);
    if (pcVar10 != (code *)0x0) {
      (*pcVar10)(iVar3,iVar4);
    }
    FUN_80013e2c(*(undefined4 *)(iVar3 + 0x68));
    *(undefined4 *)(iVar3 + 0x68) = 0;
  }
  (**(code **)(*DAT_803dca70 + 0x48))(iVar3);
  (**(code **)(*DAT_803dca78 + 0x28))(iVar3);
  if (((*(uint *)(*(int *)(iVar3 + 0x50) + 0x44) & 0x40) != 0) &&
     (FUN_80036fa4(iVar3,6), iVar4 == 0)) {
    iVar8 = 0;
    iVar6 = 0;
    for (iVar9 = 0; iVar9 < DAT_803dcb84; iVar9 = iVar9 + 1) {
      iVar5 = *(int *)(DAT_803dcb88 + iVar8);
      iVar11 = iVar6;
      if ((*(int *)(iVar5 + 0x30) == iVar3) &&
         (*(undefined4 *)(iVar5 + 0x30) = 0, *(int *)(iVar5 + 0x4c) != 0)) {
        iVar11 = iVar6 + 1;
        local_b8[iVar6] = iVar5;
      }
      iVar8 = iVar8 + 4;
      iVar6 = iVar11;
    }
    piVar7 = local_b8;
    for (iVar8 = 0; iVar8 < iVar6; iVar8 = iVar8 + 1) {
      FUN_8002cbc4(*piVar7);
      piVar7 = piVar7 + 1;
    }
    FUN_80059a50(*(undefined *)(iVar3 + 0x34));
  }
  if ((iVar4 == 0) && (*(short *)(iVar3 + 0x44) == 0x10)) {
    iVar6 = 0;
    for (iVar8 = 0; iVar8 < DAT_803dcb84; iVar8 = iVar8 + 1) {
      if (*(int *)(*(int *)(DAT_803dcb88 + iVar6) + 0xc0) == iVar3) {
        *(undefined4 *)(*(int *)(DAT_803dcb88 + iVar6) + 0xc0) = 0;
      }
      iVar6 = iVar6 + 4;
    }
  }
  iVar6 = 0;
  for (iVar8 = 0; iVar8 < DAT_803dcb84; iVar8 = iVar8 + 1) {
    if ((*(short *)(*(int *)(DAT_803dcb88 + iVar6) + 0x44) == 0x10) &&
       (piVar7 = *(int **)(*(int *)(DAT_803dcb88 + iVar6) + 0xb8), *piVar7 == iVar3)) {
      *piVar7 = 0;
      *(undefined *)((int)piVar7 + 0x8f) = 1;
    }
    iVar6 = iVar6 + 4;
  }
  if ('\0' < *(char *)(*(int *)(iVar3 + 0x50) + 0x56)) {
    FUN_80036fa4(iVar3,8);
  }
  if (*(int *)(iVar3 + 100) != 0) {
    if (*(short *)(*(int *)(iVar3 + 0x50) + 0x48) == 1) {
      FUN_800628d8(1);
    }
    if (*(int *)(*(int *)(iVar3 + 100) + 4) != 0) {
      iVar6 = FUN_8006c5c4();
      iVar8 = *(int *)(*(int *)(iVar3 + 100) + 4);
      if (iVar8 != iVar6) {
        if ((*(byte *)(*(int *)(iVar3 + 0x50) + 0x5f) & 4) == 0) {
          FUN_80054308(iVar8);
        }
        else {
          FUN_80023800(iVar8);
        }
      }
    }
    if (*(int *)(*(int *)(iVar3 + 100) + 8) != 0) {
      FUN_80023800();
    }
    iVar6 = *(int *)(*(int *)(iVar3 + 100) + 0x10);
    if ((iVar6 != 0) && (iVar6 != -1)) {
      FUN_80023800();
    }
  }
  if (*(int *)(iVar3 + 0xdc) != 0) {
    FUN_80023800();
    *(undefined4 *)(iVar3 + 0xdc) = 0;
  }
  cVar1 = *(char *)(*(int *)(iVar3 + 0x50) + 0x55);
  iVar8 = 0;
  for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
    if (*(int *)(*(int *)(iVar3 + 0x7c) + iVar8) != 0) {
      FUN_80029368();
    }
    iVar8 = iVar8 + 4;
  }
  if ((*(byte *)(iVar3 + 0xe5) & 1) != 0) {
    *(undefined2 *)(iVar3 + 0xe6) = 0;
    *(byte *)(iVar3 + 0xe5) = *(byte *)(iVar3 + 0xe5) & 0xfe;
    *(undefined *)(iVar3 + 0xf0) = 0;
    FUN_8002843c(*(undefined4 *)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4));
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x7fb,0,0x50,0);
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x7fc,0,0x32,0);
  }
  if ((*(byte *)(iVar3 + 0xe5) & 2) != 0) {
    FUN_8002a814(iVar3);
  }
  iVar6 = FUN_80037194(iVar3);
  if (iVar6 != 0) {
    FUN_80036fa4(iVar3,iVar6 + -1);
  }
  iVar6 = (int)*(short *)(iVar3 + 0x48);
  if (*(char *)(DAT_803dcba4 + iVar6) == '\0') {
    FUN_801378a8(s_objFreeObjdef__Error_____d__802cacc0);
  }
  else {
    *(char *)(DAT_803dcba4 + iVar6) = *(char *)(DAT_803dcba4 + iVar6) + -1;
    if (*(char *)(DAT_803dcba4 + iVar6) == '\0') {
      iVar6 = *(int *)(DAT_803dcba8 + iVar6 * 4);
      if (*(int *)(iVar6 + 0x30) != 0) {
        FUN_80023800();
      }
      if (*(int *)(iVar6 + 0x34) != 0) {
        FUN_80023800();
      }
      FUN_80023800(iVar6);
    }
  }
  if (-1 < *(short *)(iVar3 + 0xb4)) {
    if (iVar4 == 0) {
      (**(code **)(*DAT_803dca54 + 0x4c))();
    }
    *(undefined2 *)(iVar3 + 0xb4) = 0xffff;
  }
  if (((*(ushort *)(iVar3 + 6) & 0x2000) != 0) && (*(int *)(iVar3 + 0x4c) != 0)) {
    FUN_80023800();
  }
  FUN_80023800(iVar3);
  FUN_80286128();
  return;
}

