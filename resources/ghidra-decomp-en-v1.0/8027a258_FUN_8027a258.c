// Function: FUN_8027a258
// Entry: 8027a258
// Size: 92 bytes

void FUN_8027a258(int param_1)

{
  uint uVar1;
  undefined uVar2;
  
  if (*(uint *)(param_1 + 0xf4) == 0xffffffff) {
    return;
  }
  if (*(byte *)(param_1 + 0x121) == 0xff) {
    return;
  }
  uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
  uVar2 = (undefined)uVar1;
  if (*(byte *)(param_1 + 0x122) == 0xff) {
    (&DAT_803cab50)[uVar1] = uVar2;
    return;
  }
  (&DAT_803caad0)[(uint)*(byte *)(param_1 + 0x121) + (uint)*(byte *)(param_1 + 0x122) * 0x10] =
       uVar2;
  return;
}

