// Function: FUN_80037e24
// Entry: 80037e24
// Size: 72 bytes

void FUN_80037e24(int param_1,int param_2,ushort param_3)

{
  byte bVar1;
  
  bVar1 = *(byte *)(param_1 + 0xeb);
  *(byte *)(param_1 + 0xeb) = bVar1 + 1;
  *(int *)(param_1 + (uint)bVar1 * 4 + 200) = param_2;
  *(int *)(param_2 + 0xc4) = param_1;
  *(ushort *)(param_2 + 0xb0) = *(ushort *)(param_2 + 0xb0) & 0xfff8;
  *(ushort *)(param_2 + 0xb0) = *(ushort *)(param_2 + 0xb0) | param_3;
  *(undefined *)(param_2 + 0xe5) = 0;
  return;
}

