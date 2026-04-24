// Function: FUN_80197360
// Entry: 80197360
// Size: 196 bytes

void FUN_80197360(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *piVar2 = (int)*(char *)(param_2 + 0x19);
  piVar2[2] = (int)*(short *)(param_2 + 0x1a) << 8;
  *(char *)(piVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1c);
  piVar2[3] = (int)*(char *)(param_2 + 0x18) << 8;
  uVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  *(byte *)(piVar2 + 5) = (byte)((uVar1 & 1) << 6) | *(byte *)(piVar2 + 5) & 0xbf;
  if ((uVar1 & 1) != 0) {
    piVar2[4] = piVar2[2];
    *(byte *)(piVar2 + 5) = *(byte *)(piVar2 + 5) & 0xdf | 0x20;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  return;
}

