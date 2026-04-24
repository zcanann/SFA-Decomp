// Function: FUN_80238c8c
// Entry: 80238c8c
// Size: 36 bytes

void FUN_80238c8c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0xbf;
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0x7f;
  return;
}

