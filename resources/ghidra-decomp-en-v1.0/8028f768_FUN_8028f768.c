// Function: FUN_8028f768
// Entry: 8028f768
// Size: 120 bytes

void FUN_8028f768(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int local_18;
  undefined4 local_14;
  undefined4 local_10;
  
  local_14 = 0xffffffff;
  local_10 = 0;
  local_18 = param_1;
  iVar1 = FUN_8028f920(FUN_8028f85c,&local_18,param_2,param_3);
  if (param_1 != 0) {
    iVar2 = -2;
    if (iVar1 != -1) {
      iVar2 = iVar1;
    }
    *(undefined *)(param_1 + iVar2) = 0;
  }
  return;
}

