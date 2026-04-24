// Function: FUN_80291d74
// Entry: 80291d74
// Size: 64 bytes

int FUN_80291d74(int param_1,int param_2,int param_3)

{
  uint uVar1;
  byte *pbVar2;
  byte *pbVar3;
  int iVar4;
  
  pbVar2 = (byte *)(param_1 + -1);
  pbVar3 = (byte *)(param_2 + -1);
  iVar4 = param_3 + 1;
  while( true ) {
    iVar4 = iVar4 + -1;
    if (iVar4 == 0) {
      return 0;
    }
    pbVar2 = pbVar2 + 1;
    uVar1 = (uint)*pbVar2;
    pbVar3 = pbVar3 + 1;
    if (uVar1 != *pbVar3) break;
    if (uVar1 == 0) {
      return 0;
    }
  }
  return uVar1 - *pbVar3;
}

