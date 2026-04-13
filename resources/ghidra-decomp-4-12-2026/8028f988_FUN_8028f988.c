// Function: FUN_8028f988
// Entry: 8028f988
// Size: 76 bytes

undefined4 FUN_8028f988(int param_1,int param_2,int param_3)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)(param_1 + -1);
  pbVar3 = (byte *)(param_2 + -1);
  iVar1 = param_3 + 1;
  do {
    iVar1 = iVar1 + -1;
    if (iVar1 == 0) {
      return 0;
    }
    pbVar2 = pbVar2 + 1;
    pbVar3 = pbVar3 + 1;
  } while (*pbVar2 == *pbVar3);
  if (*pbVar3 <= *pbVar2) {
    return 1;
  }
  return 0xffffffff;
}

