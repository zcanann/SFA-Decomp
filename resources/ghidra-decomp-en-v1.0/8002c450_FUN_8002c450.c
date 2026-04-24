// Function: FUN_8002c450
// Entry: 8002c450
// Size: 444 bytes

void FUN_8002c450(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined local_28;
  undefined uStack39;
  
  iVar2 = FUN_802860dc();
  if (iVar2 < DAT_803dcbb8) {
    if (*(char *)(DAT_803dcba4 + iVar2) == '\0') {
      iVar1 = iVar2 * 4;
      iVar5 = *(int *)(DAT_803dcbbc + iVar1);
      iVar6 = *(int *)(DAT_803dcbbc + iVar1 + 4) - iVar5;
      iVar3 = FUN_80023cc8(iVar6,0xe,0);
      if (iVar3 == 0) {
        iVar3 = 0;
      }
      else {
        FUN_80048f48(0x3e,iVar3,iVar5,iVar6);
        if (*(int *)(iVar3 + 0x20) != 0) {
          *(int *)(iVar3 + 0x20) = iVar3 + *(int *)(iVar3 + 0x20);
        }
        if (*(int *)(iVar3 + 0x24) != 0) {
          *(int *)(iVar3 + 0x24) = iVar3 + *(int *)(iVar3 + 0x24);
        }
        if (*(int *)(iVar3 + 0x28) != 0) {
          *(int *)(iVar3 + 0x28) = iVar3 + *(int *)(iVar3 + 0x28);
        }
        *(int *)(iVar3 + 8) = iVar3 + *(int *)(iVar3 + 8);
        *(int *)(iVar3 + 0xc) = iVar3 + *(int *)(iVar3 + 0xc);
        *(int *)(iVar3 + 0x10) = iVar3 + *(int *)(iVar3 + 0x10);
        if (*(int *)(iVar3 + 0x18) != 0) {
          *(int *)(iVar3 + 0x18) = iVar3 + *(int *)(iVar3 + 0x18);
        }
        if (*(int *)(iVar3 + 0x40) != 0) {
          *(int *)(iVar3 + 0x40) = iVar3 + *(int *)(iVar3 + 0x40);
        }
        if (*(int *)(iVar3 + 0x1c) != 0) {
          *(int *)(iVar3 + 0x1c) = iVar3 + *(int *)(iVar3 + 0x1c);
        }
        *(int *)(iVar3 + 0x2c) = iVar3 + *(int *)(iVar3 + 0x2c);
        *(undefined4 *)(iVar3 + 0x30) = 0;
        *(undefined4 *)(iVar3 + 0x34) = 0;
        if (-1 < *(char *)(iVar3 + 0x5d)) {
          uVar4 = FUN_8002c36c((int)*(char *)(iVar3 + 0x5d),&local_28);
          *(undefined4 *)(iVar3 + 0x30) = uVar4;
          *(undefined *)(iVar3 + 0x5c) = uStack39;
          FUN_80064744(iVar3);
        }
        *(int *)(DAT_803dcba8 + iVar1) = iVar3;
        *(undefined *)(DAT_803dcba4 + iVar2) = 1;
      }
    }
    else {
      *(char *)(DAT_803dcba4 + iVar2) = *(char *)(DAT_803dcba4 + iVar2) + '\x01';
      iVar3 = *(int *)(DAT_803dcba8 + iVar2 * 4);
    }
  }
  else {
    iVar3 = 0;
  }
  FUN_80286128(iVar3);
  return;
}

