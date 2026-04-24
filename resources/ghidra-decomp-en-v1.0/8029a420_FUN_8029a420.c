// Function: FUN_8029a420
// Entry: 8029a420
// Size: 136 bytes

void FUN_8029a420(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar2 + 0x8c8) != 'B') && (iVar1 = FUN_80080204(), iVar1 == 0)) {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
  }
  *(byte *)(iVar2 + 0x3f6) = *(byte *)(iVar2 + 0x3f6) & 0xbf;
  *(undefined2 *)(iVar2 + 0x80a) = 0xffff;
  return;
}

