// Function: FUN_802846bc
// Entry: 802846bc
// Size: 40 bytes

undefined4 FUN_802846bc(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803defc4 + param_1 * 0xf4;
  if (*(char *)(iVar1 + 0xec) == '\0') {
    return 0xffffffff;
  }
  return *(undefined4 *)(iVar1 + 0xe8);
}

