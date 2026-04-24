// Function: FUN_80036944
// Entry: 80036944
// Size: 172 bytes

void FUN_80036944(void)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < DAT_803dcbe0; iVar1 = iVar1 + 1) {
    if (((*(uint *)(*(int *)(*(int *)(DAT_803dcbe4 + iVar2) + 0x50) + 0x44) & 0x40) == 0) &&
       (*(char *)(*(int *)(DAT_803dcbe4 + iVar2) + 0xae) != 'd')) {
      FUN_8002c784();
    }
    iVar2 = iVar2 + 4;
  }
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < DAT_803dcbe0; iVar1 = iVar1 + 1) {
    FUN_80032410(*(undefined4 *)(DAT_803dcbe4 + iVar2),1);
    iVar2 = iVar2 + 4;
  }
  return;
}

