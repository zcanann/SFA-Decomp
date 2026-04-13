// Function: FUN_80239e70
// Entry: 80239e70
// Size: 108 bytes

void FUN_80239e70(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if (*puVar1 != 0) {
    FUN_800238c4(*puVar1);
    *puVar1 = 0;
  }
  *(byte *)((int)puVar1 + 0x1b) = *(byte *)((int)puVar1 + 0x1b) & 0xf;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  return;
}

