// Function: FUN_80193f30
// Entry: 80193f30
// Size: 476 bytes

void FUN_80193f30(int param_1)

{
  int iVar1;
  byte bVar3;
  int iVar2;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  iVar1 = FUN_8005aeec();
  if (iVar1 == 0) {
    pbVar4[1] = pbVar4[1] & 0xfe;
    pbVar4[1] = pbVar4[1] | 4;
  }
  else {
    bVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x18));
    pbVar4[2] = bVar3;
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
      iVar2 = FUN_80065640();
      if (iVar2 != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if (((pbVar4[1] & 2) != 0) && (iVar2 = FUN_80065640(), iVar2 == 0)) {
        FUN_80065574(*(undefined *)(iVar5 + 0x1d),*(undefined4 *)(param_1 + 0x30),(int)(char)*pbVar4
                    );
        pbVar4[1] = pbVar4[1] & 0xfd;
      }
    }
    if ((((*(byte *)(iVar5 + 0x1c) & 4) != 0) && (*(char *)(iVar5 + 0x1b) != '\0')) &&
       ((pbVar4[1] & 4) != 0)) {
      FUN_80193dbc(iVar1,param_1,pbVar4,iVar5);
      pbVar4[1] = pbVar4[1] & 0xfb;
    }
  }
  return;
}

