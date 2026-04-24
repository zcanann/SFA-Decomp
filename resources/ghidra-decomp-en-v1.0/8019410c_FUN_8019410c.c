// Function: FUN_8019410c
// Entry: 8019410c
// Size: 304 bytes

void FUN_8019410c(int param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  *pbVar3 = *(byte *)(param_2 + 0x1c) & 1;
  pbVar3[1] = 0;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  if ((iVar1 != 0) && (*pbVar3 = *pbVar3 ^ 1, *(char *)(param_2 + 0x1a) == '\x01')) {
    pbVar3[1] = pbVar3[1] | 1;
  }
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  iVar1 = FUN_8005aeec();
  if (((iVar1 != 0) && ((*(byte *)(param_2 + 0x1c) & 4) != 0)) &&
     (*(char *)(param_2 + 0x1b) != '\0')) {
    FUN_80193dbc(iVar1,param_1,pbVar3,param_2);
  }
  pbVar3[1] = pbVar3[1] | 2;
  if ((*(byte *)(param_2 + 0x1c) & 4) != 0) {
    pbVar3[1] = pbVar3[1] | 4;
  }
  bVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  pbVar3[2] = bVar2;
  pbVar3[3] = bVar2;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

