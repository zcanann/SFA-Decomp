// Function: FUN_80194688
// Entry: 80194688
// Size: 304 bytes

void FUN_80194688(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  *pbVar3 = *(byte *)(param_2 + 0x1c) & 1;
  pbVar3[1] = 0;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  if ((uVar1 != 0) && (*pbVar3 = *pbVar3 ^ 1, *(char *)(param_2 + 0x1a) == '\x01')) {
    pbVar3[1] = pbVar3[1] | 1;
  }
  iVar2 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar2 = FUN_8005b068(iVar2);
  if (((iVar2 != 0) && ((*(byte *)(param_2 + 0x1c) & 4) != 0)) &&
     (*(char *)(param_2 + 0x1b) != '\0')) {
    FUN_80194338(iVar2,param_1,(char *)pbVar3,param_2);
  }
  pbVar3[1] = pbVar3[1] | 2;
  if ((*(byte *)(param_2 + 0x1c) & 4) != 0) {
    pbVar3[1] = pbVar3[1] | 4;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  pbVar3[2] = (byte)uVar1;
  pbVar3[3] = (byte)uVar1;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

