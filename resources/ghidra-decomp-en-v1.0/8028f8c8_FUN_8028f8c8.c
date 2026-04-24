// Function: FUN_8028f8c8
// Entry: 8028f8c8
// Size: 88 bytes

undefined4 FUN_8028f8c8(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_8028ec00(param_2,1,param_3,param_1);
  if (param_3 != iVar1) {
    param_1 = 0;
  }
  return param_1;
}

