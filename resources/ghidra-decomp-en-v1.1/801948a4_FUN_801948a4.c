// Function: FUN_801948a4
// Entry: 801948a4
// Size: 216 bytes

void FUN_801948a4(int param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  pbVar4 = *(byte **)(param_1 + 0xb8);
  pbVar4[1] = *(byte *)(param_2 + 0x1b);
  pbVar4[4] = (byte)(1 << (uint)*(byte *)(param_2 + 0x1c));
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  if ((pbVar4[4] & uVar2) != 0) {
    pbVar4[1] = pbVar4[1] ^ 1;
  }
  iVar3 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  FUN_8005b068(iVar3);
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  bVar1 = pbVar4[4] & (byte)uVar2;
  pbVar4[2] = bVar1;
  pbVar4[3] = bVar1;
  *pbVar4 = *pbVar4 | 1;
  return;
}

