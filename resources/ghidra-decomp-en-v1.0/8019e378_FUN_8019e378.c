// Function: FUN_8019e378
// Entry: 8019e378
// Size: 116 bytes

void FUN_8019e378(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if (*(char *)(param_2 + 0x19) == '\0') {
    *(undefined *)(iVar1 + 0x15c) = 0x28;
    *(undefined *)(iVar1 + 0x15d) = 0;
    *(undefined *)(iVar1 + 0x15e) = 0;
    *(undefined *)(iVar1 + 0x15f) = 0x46;
    *(undefined *)((int)param_1 + 0xad) = 1;
    *(undefined4 *)(iVar1 + 0x158) = 0;
  }
  FUN_80037964(param_1,2);
  return;
}

