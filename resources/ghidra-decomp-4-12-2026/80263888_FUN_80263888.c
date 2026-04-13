// Function: FUN_80263888
// Entry: 80263888
// Size: 84 bytes

void FUN_80263888(int *param_1)

{
  int iVar1;
  int *local_c [2];
  
  iVar1 = FUN_8025f52c(*param_1,local_c);
  if (-1 < iVar1) {
    *param_1 = -1;
    FUN_8025f5e4(local_c[0],0);
  }
  return;
}

