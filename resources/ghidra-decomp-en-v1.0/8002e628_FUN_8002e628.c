// Function: FUN_8002e628
// Entry: 8002e628
// Size: 876 bytes

void FUN_8002e628(void)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined uVar7;
  int iVar4;
  int *piVar5;
  int iVar6;
  code *pcVar8;
  int iVar9;
  int local_28;
  int local_24 [9];
  
  uVar3 = FUN_802860dc();
  DAT_803dcb78 = uVar3 & 0xff;
  iVar9 = (int)sRam803dcb7e;
  uVar2 = uVar3 & 1;
  if (uVar2 == 0) {
    FUN_80065604();
  }
  FUN_8002e47c();
  FUN_80035630(DAT_803dcb84);
  for (iVar6 = iRam803dcb80; (iVar6 != 0 && (*(char *)(iVar6 + 0xae) == 'd'));
      iVar6 = *(int *)(iVar6 + iVar9)) {
    FUN_8002c784(iVar6);
  }
  while ((iVar6 != 0 && ((*(uint *)(*(int *)(iVar6 + 0x50) + 0x44) & 0x40) != 0))) {
    FUN_8002c784(iVar6);
    uVar7 = FUN_8000e340(iVar6);
    *(undefined *)(iVar6 + 0x35) = uVar7;
    iVar6 = *(int *)(iVar6 + iVar9);
  }
  if (uVar2 == 0) {
    FUN_80036944();
  }
  for (; iVar6 != 0; iVar6 = *(int *)(iVar6 + iVar9)) {
    iVar4 = *(int *)(iVar6 + 0x54);
    if (iVar4 == 0) {
      FUN_8002c784(iVar6);
    }
    else if (((*(byte *)(iVar4 + 0x62) & 8) == 0) || ((*(ushort *)(iVar4 + 0x60) & 1) == 0)) {
      FUN_8002c784(iVar6);
    }
  }
  piVar5 = (int *)FUN_80036f50(0,local_24);
  if (local_24[0] == 0) {
    iVar6 = 0;
  }
  else {
    iVar6 = *piVar5;
  }
  if ((iVar6 != 0) && (*(int *)(iVar6 + 200) != 0)) {
    *(undefined4 *)(*(int *)(iVar6 + 200) + 0x30) = *(undefined4 *)(iVar6 + 0x30);
    FUN_8002c784(*(undefined4 *)(iVar6 + 200));
  }
  if (uVar2 != 0) goto LAB_8002e8e0;
  FUN_80034cdc(DAT_803dcb84);
  for (iVar6 = iRam803dcb80; iVar6 != 0; iVar6 = *(int *)(iVar6 + iVar9)) {
    if ((*(ushort *)(iVar6 + 0xb0) & 0x2000) == 0) {
      sVar1 = *(short *)(iVar6 + 0x46);
      if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
        FUN_802b5840(iVar6);
      }
      else {
        if ((*(int **)(iVar6 + 0x68) == (int *)0x0) ||
           (pcVar8 = *(code **)(**(int **)(iVar6 + 0x68) + 0xc), pcVar8 == (code *)0x0))
        goto LAB_8002e804;
        (*pcVar8)(iVar6);
      }
      FUN_8000e10c(iVar6,iVar6 + 0x18,iVar6 + 0x1c,iVar6 + 0x20);
    }
LAB_8002e804:
  }
  piVar5 = (int *)FUN_80036f50(0,&local_28);
  if (local_28 == 0) {
    iVar9 = 0;
  }
  else {
    iVar9 = *piVar5;
  }
  if ((iVar9 != 0) && (*(int *)(iVar9 + 200) != 0)) {
    *(undefined4 *)(*(int *)(iVar9 + 200) + 0x30) = *(undefined4 *)(iVar9 + 0x30);
    iVar9 = *(int *)(iVar9 + 200);
    if ((*(ushort *)(iVar9 + 0xb0) & 0x2000) == 0) {
      sVar1 = *(short *)(iVar9 + 0x46);
      if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
        FUN_802b5840(iVar9);
      }
      else {
        if ((*(int **)(iVar9 + 0x68) == (int *)0x0) ||
           (pcVar8 = *(code **)(**(int **)(iVar9 + 0x68) + 0xc), pcVar8 == (code *)0x0))
        goto LAB_8002e8c8;
        (*pcVar8)(iVar9);
      }
      FUN_8000e10c(iVar9,iVar9 + 0x18,iVar9 + 0x1c,iVar9 + 0x20);
    }
  }
LAB_8002e8c8:
  (**(code **)(*DAT_803dca98 + 4))(DAT_803db410);
LAB_8002e8e0:
  if ((uVar3 & 2) == 0) {
    (**(code **)(*DAT_803dca7c + 0xc))(0,0,0);
    (**(code **)(*DAT_803dca78 + 0xc))(0,DAT_803db410,0,0);
  }
  if (uVar2 == 0) {
    FUN_800323d0();
    (**(code **)(*DAT_803dca54 + 0x28))();
    (**(code **)(*DAT_803dca54 + 0x18))();
    (**(code **)(*DAT_803dca50 + 8))(DAT_803db410);
  }
  FUN_80286128();
  return;
}

