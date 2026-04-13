// Function: FUN_8027a790
// Entry: 8027a790
// Size: 160 bytes

void FUN_8027a790(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803deee8 + param_1 * 0x404;
  if (*(int *)(iVar1 + 0x34) != 0) {
    FUN_8027979c(iVar1);
    *(uint *)(iVar1 + 0x118) = *(uint *)(iVar1 + 0x118) & 0xfffffffc;
    *(undefined4 *)(iVar1 + 0x114) = *(undefined4 *)(iVar1 + 0x114);
    *(undefined4 *)(iVar1 + 0x110) = 0;
    FUN_8027a2fc(iVar1);
  }
  if (*(char *)(iVar1 + 0x11c) != '\0') {
    FUN_80273f50(param_1);
  }
  FUN_80283ba0(param_1);
  return;
}

