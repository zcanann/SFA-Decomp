// Function: FUN_8021e544
// Entry: 8021e544
// Size: 128 bytes

undefined4 FUN_8021e544(int param_1)

{
  int iVar1;
  
  FUN_800394a0();
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x9fd) = *(byte *)(iVar1 + 0x9fd) & 0xfe;
  *(byte *)(iVar1 + 0xc49) = *(byte *)(iVar1 + 0xc49) & 0xf7;
  *(byte *)(iVar1 + 0xc49) = *(byte *)(iVar1 + 0xc49) & 0xfd | 2;
  if (*(char *)(iVar1 + 0xc4b) == '\0') {
    *(byte *)(iVar1 + 0xc4a) = *(byte *)(iVar1 + 0xc4a) & 0x7f | 0x80;
  }
  return 0;
}

