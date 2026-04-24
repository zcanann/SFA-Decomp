// Function: FUN_80012ec0
// Entry: 80012ec0
// Size: 248 bytes

int FUN_80012ec0(int param_1,int param_2,int param_3,uint param_4,int param_5,int param_6)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  byte bVar4;
  uint uVar5;
  byte *pbVar6;
  
  iVar2 = param_5 * 3;
  if (param_6 >> 3 == 0) {
    uVar5 = (uint)*(byte *)(param_1 + iVar2) | (*(byte *)(param_1 + iVar2 + 1) & 0xf) << 8;
    uVar1 = param_5 << 5;
  }
  else {
    uVar5 = (uint)(*(byte *)(param_1 + iVar2 + 1) >> 4) | (uint)*(byte *)(param_1 + iVar2 + 2) << 4;
    uVar1 = param_5 << 5 | 0x10;
  }
  pbVar6 = (byte *)(param_3 + uVar1);
  pbVar3 = (byte *)(param_3 + (param_5 << 5 | param_6 * 2 + ((int)param_4 >> 3)));
  iVar2 = (int)pbVar3 - (int)pbVar6;
  if (pbVar6 < pbVar3) {
    do {
      for (bVar4 = *pbVar6; bVar4 != 0; bVar4 = bVar4 & bVar4 - 1) {
        uVar5 = uVar5 + 1;
      }
      pbVar6 = pbVar6 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  for (uVar1 = 0xffU >> 8 - (param_4 & 7) & 0xff & (uint)*pbVar6; uVar1 != 0;
      uVar1 = uVar1 & uVar1 - 1) {
    uVar5 = uVar5 + 1;
  }
  return param_2 + uVar5 * 4;
}

