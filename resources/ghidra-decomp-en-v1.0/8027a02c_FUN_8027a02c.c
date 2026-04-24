// Function: FUN_8027a02c
// Entry: 8027a02c
// Size: 160 bytes

void FUN_8027a02c(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803de268 + param_1 * 0x404;
  if (*(int *)(iVar1 + 0x34) != 0) {
    FUN_80279038(iVar1);
    *(uint *)(iVar1 + 0x118) = *(uint *)(iVar1 + 0x118) & 0xfffffffc;
    *(undefined4 *)(iVar1 + 0x114) = *(undefined4 *)(iVar1 + 0x114);
    *(undefined4 *)(iVar1 + 0x110) = 0;
    FUN_80279b98(iVar1);
  }
  if (*(char *)(iVar1 + 0x11c) != '\0') {
    FUN_802737ec(param_1);
  }
  FUN_8028343c(param_1);
  return;
}

