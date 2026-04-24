// Function: FUN_8028f228
// Entry: 8028f228
// Size: 76 bytes

undefined4 FUN_8028f228(int param_1,int param_2,int param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  
  pbVar1 = (byte *)(param_1 + -1);
  pbVar2 = (byte *)(param_2 + -1);
  param_3 = param_3 + 1;
  do {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
      return 0;
    }
    pbVar1 = pbVar1 + 1;
    pbVar2 = pbVar2 + 1;
  } while (*pbVar1 == *pbVar2);
  if (*pbVar2 <= *pbVar1) {
    return 1;
  }
  return 0xffffffff;
}

