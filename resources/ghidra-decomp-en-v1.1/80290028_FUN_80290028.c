// Function: FUN_80290028
// Entry: 80290028
// Size: 88 bytes

undefined4 * FUN_80290028(undefined4 *param_1,uint param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_8028f360(param_2,1,param_3,param_1);
  if (param_3 != iVar1) {
    param_1 = (undefined4 *)0x0;
  }
  return param_1;
}

