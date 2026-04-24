// Function: FUN_801944ac
// Entry: 801944ac
// Size: 476 bytes

void FUN_801944ac(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar1 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005b068(iVar1);
  if (iVar1 == 0) {
    pbVar4[1] = pbVar4[1] & 0xfe;
    pbVar4[1] = pbVar4[1] | 4;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x18));
    pbVar4[2] = (byte)uVar2;
    if (pbVar4[3] != pbVar4[2]) {
      *pbVar4 = *pbVar4 ^ 1;
      if (*(char *)(iVar5 + 0x1a) == '\x01') {
        pbVar4[1] = pbVar4[1] | 1;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 4) != 0) {
        pbVar4[1] = pbVar4[1] | 4;
      }
    }
    pbVar4[3] = pbVar4[2];
    if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
      iVar3 = FUN_800657bc();
      if (iVar3 != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if (((pbVar4[1] & 2) != 0) && (iVar3 = FUN_800657bc(), iVar3 == 0)) {
        FUN_800656f0((uint)*(byte *)(iVar5 + 0x1d),*(int *)(param_1 + 0x30),(int)(char)*pbVar4);
        pbVar4[1] = pbVar4[1] & 0xfd;
      }
    }
    if ((((*(byte *)(iVar5 + 0x1c) & 4) != 0) && (*(char *)(iVar5 + 0x1b) != '\0')) &&
       ((pbVar4[1] & 4) != 0)) {
      FUN_80194338(iVar1,param_1,(char *)pbVar4,iVar5);
      pbVar4[1] = pbVar4[1] & 0xfb;
    }
  }
  return;
}

