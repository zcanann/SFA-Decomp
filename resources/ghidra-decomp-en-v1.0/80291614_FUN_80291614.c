// Function: FUN_80291614
// Entry: 80291614
// Size: 64 bytes

int FUN_80291614(int param_1,int param_2,int param_3)

{
  uint uVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)(param_1 + -1);
  pbVar3 = (byte *)(param_2 + -1);
  param_3 = param_3 + 1;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
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

