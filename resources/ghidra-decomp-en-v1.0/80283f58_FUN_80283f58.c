// Function: FUN_80283f58
// Entry: 80283f58
// Size: 40 bytes

undefined4 FUN_80283f58(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803de344 + param_1 * 0xf4;
  if (*(char *)(iVar1 + 0xec) == '\0') {
    return 0xffffffff;
  }
  return *(undefined4 *)(iVar1 + 0xe8);
}

