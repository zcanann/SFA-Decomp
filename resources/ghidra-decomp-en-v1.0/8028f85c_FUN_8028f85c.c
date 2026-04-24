// Function: FUN_8028f85c
// Entry: 8028f85c
// Size: 108 bytes

undefined4 FUN_8028f85c(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1[2];
  iVar2 = param_1[1] - iVar1;
  if ((uint)(iVar1 + param_3) <= (uint)param_1[1]) {
    iVar2 = param_3;
  }
  FUN_80003494(*param_1 + iVar1,param_2,iVar2);
  param_1[2] = param_1[2] + iVar2;
  return 1;
}

