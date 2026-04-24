// Function: FUN_8028fec8
// Entry: 8028fec8
// Size: 120 bytes

void FUN_8028fec8(int param_1,char *param_2,char *param_3)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  local_18[1] = 0xffffffff;
  local_18[2] = 0;
  local_18[0] = param_1;
  iVar1 = FUN_80290080(FUN_8028ffbc,local_18,param_2,param_3);
  if (param_1 != 0) {
    iVar2 = -2;
    if (iVar1 != -1) {
      iVar2 = iVar1;
    }
    *(undefined *)(param_1 + iVar2) = 0;
  }
  return;
}

