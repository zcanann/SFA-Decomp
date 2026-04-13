// Function: FUN_801947d4
// Entry: 801947d4
// Size: 208 bytes

void FUN_801947d4(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar1 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005b068(iVar1);
  if (iVar1 == 0) {
    *pbVar4 = *pbVar4 | 1;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x18));
    pbVar4[2] = pbVar4[4] & (byte)uVar2;
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

