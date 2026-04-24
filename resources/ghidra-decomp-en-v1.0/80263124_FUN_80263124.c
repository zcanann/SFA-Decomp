// Function: FUN_80263124
// Entry: 80263124
// Size: 84 bytes

void FUN_80263124(undefined4 *param_1)

{
  int iVar1;
  undefined4 local_c [2];
  
  iVar1 = FUN_8025edc8(*param_1,local_c);
  if (-1 < iVar1) {
    *param_1 = 0xffffffff;
    FUN_8025ee80(local_c[0],0);
  }
  return;
}

