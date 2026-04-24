// Function: FUN_801b75c8
// Entry: 801b75c8
// Size: 100 bytes

void FUN_801b75c8(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  if ((*(byte *)((int)puVar1 + 0x1d) & 4) != 0) {
    *(byte *)((int)puVar1 + 0x1d) = *(byte *)((int)puVar1 + 0x1d) & 0xfb;
  }
  FUN_80023800(*puVar1);
  FUN_80023800(puVar1[1]);
  (&DAT_803dbf20)[*(byte *)((int)puVar1 + 0x1f)] = 0;
  return;
}

