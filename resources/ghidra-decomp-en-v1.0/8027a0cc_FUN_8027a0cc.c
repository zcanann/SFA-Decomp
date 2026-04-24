// Function: FUN_8027a0cc
// Entry: 8027a0cc
// Size: 272 bytes

undefined4 FUN_8027a0cc(int param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  
  uVar6 = 0xffffffff;
  if (DAT_803de238 != '\0') {
    if ((param_1 == -1) || (iVar3 = FUN_80279004(), iVar3 == 0)) {
      uVar4 = 0xffffffff;
    }
    else {
      uVar4 = *(uint *)(iVar3 + 0xc);
    }
    while (uVar4 != 0xffffffff) {
      uVar2 = uVar4 & 0xff;
      iVar3 = DAT_803de268 + uVar2 * 0x404;
      uVar5 = *(uint *)(iVar3 + 0xec);
      bVar1 = uVar4 == *(uint *)(iVar3 + 0xf4);
      uVar4 = uVar5;
      if (bVar1) {
        if (*(int *)(iVar3 + 0x34) != 0) {
          FUN_80279038(iVar3);
          *(uint *)(iVar3 + 0x118) = *(uint *)(iVar3 + 0x118) & 0xfffffffc;
          *(undefined4 *)(iVar3 + 0x114) = *(undefined4 *)(iVar3 + 0x114);
          *(undefined4 *)(iVar3 + 0x110) = 0;
          FUN_80279b98(iVar3);
        }
        if (*(char *)(iVar3 + 0x11c) != '\0') {
          FUN_802737ec(uVar2);
        }
        FUN_8028343c(uVar2);
        uVar6 = 0;
      }
    }
  }
  return uVar6;
}

