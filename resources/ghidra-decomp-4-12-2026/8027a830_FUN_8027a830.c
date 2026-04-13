// Function: FUN_8027a830
// Entry: 8027a830
// Size: 272 bytes

undefined4 FUN_8027a830(uint param_1)

{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  
  uVar6 = 0xffffffff;
  if (DAT_803deeb8 != '\0') {
    if ((param_1 == 0xffffffff) || (puVar3 = FUN_80279768(param_1), puVar3 == (undefined4 *)0x0)) {
      uVar4 = 0xffffffff;
    }
    else {
      uVar4 = puVar3[3];
    }
    while (uVar4 != 0xffffffff) {
      uVar2 = uVar4 & 0xff;
      iVar7 = DAT_803deee8 + uVar2 * 0x404;
      uVar5 = *(uint *)(iVar7 + 0xec);
      bVar1 = uVar4 == *(uint *)(iVar7 + 0xf4);
      uVar4 = uVar5;
      if (bVar1) {
        if (*(int *)(iVar7 + 0x34) != 0) {
          FUN_8027979c(iVar7);
          *(uint *)(iVar7 + 0x118) = *(uint *)(iVar7 + 0x118) & 0xfffffffc;
          *(undefined4 *)(iVar7 + 0x114) = *(undefined4 *)(iVar7 + 0x114);
          *(undefined4 *)(iVar7 + 0x110) = 0;
          FUN_8027a2fc(iVar7);
        }
        if (*(char *)(iVar7 + 0x11c) != '\0') {
          FUN_80273f50(uVar2);
        }
        FUN_80283ba0(uVar2);
        uVar6 = 0;
      }
    }
  }
  return uVar6;
}

