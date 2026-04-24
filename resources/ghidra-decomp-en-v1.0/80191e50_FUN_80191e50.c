// Function: FUN_80191e50
// Entry: 80191e50
// Size: 212 bytes

void FUN_80191e50(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *puVar2 = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x19) << 9);
  puVar2[2] = (int)*(short *)(param_2 + 0x1a) << 8;
  *(char *)(puVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1c);
  puVar2[3] = (int)*(char *)(param_2 + 0x18) << 8;
  uVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  *(byte *)(puVar2 + 5) = (byte)((uVar1 & 1) << 6) | *(byte *)(puVar2 + 5) & 0xbf;
  if ((uVar1 & 1) != 0) {
    puVar2[4] = puVar2[2];
    *(byte *)(puVar2 + 5) = *(byte *)(puVar2 + 5) & 0xdf | 0x20;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

