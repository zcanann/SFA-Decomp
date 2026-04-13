// Function: FUN_801b7b7c
// Entry: 801b7b7c
// Size: 100 bytes

void FUN_801b7b7c(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if ((*(byte *)((int)puVar1 + 0x1d) & 4) != 0) {
    *(byte *)((int)puVar1 + 0x1d) = *(byte *)((int)puVar1 + 0x1d) & 0xfb;
  }
  FUN_800238c4(*puVar1);
  FUN_800238c4(puVar1[1]);
  (&DAT_803dcb88)[*(byte *)((int)puVar1 + 0x1f)] = 0;
  return;
}

