// Function: FUN_80194258
// Entry: 80194258
// Size: 208 bytes

void FUN_80194258(int param_1)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  iVar1 = FUN_8005aeec();
  if (iVar1 == 0) {
    *pbVar4 = *pbVar4 | 1;
  }
  else {
    bVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x18));
    pbVar4[2] = pbVar4[4] & bVar2;
    if (pbVar4[3] != pbVar4[2]) {
      pbVar4[1] = pbVar4[1] ^ 1;
      *pbVar4 = *pbVar4 | 1;
    }
    pbVar4[3] = pbVar4[2];
    if ((*pbVar4 & 1) != 0) {
      *pbVar4 = *pbVar4 & 0xfe;
    }
  }
  return;
}

