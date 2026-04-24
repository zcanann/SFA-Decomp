// Function: FUN_80194328
// Entry: 80194328
// Size: 216 bytes

void FUN_80194328(int param_1,int param_2)

{
  byte bVar1;
  byte *pbVar2;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  pbVar2 = *(byte **)(param_1 + 0xb8);
  pbVar2[1] = *(byte *)(param_2 + 0x1b);
  pbVar2[4] = (byte)(1 << (uint)*(byte *)(param_2 + 0x1c));
  bVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  if ((pbVar2[4] & bVar1) != 0) {
    pbVar2[1] = pbVar2[1] ^ 1;
  }
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  FUN_8005aeec();
  bVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  pbVar2[2] = pbVar2[4] & bVar1;
  pbVar2[3] = pbVar2[4] & bVar1;
  *pbVar2 = *pbVar2 | 1;
  return;
}

