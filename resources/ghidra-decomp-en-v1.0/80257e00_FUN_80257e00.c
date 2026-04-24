// Function: FUN_80257e00
// Entry: 80257e00
// Size: 116 bytes

void FUN_80257e00(undefined4 param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = 9;
  do {
    *param_2 = iVar1;
    FUN_80257bb8(param_1,iVar1,param_2 + 1,param_2 + 2,param_2 + 3);
    iVar1 = iVar1 + 1;
    param_2 = param_2 + 4;
  } while (iVar1 < 0x1a);
  *param_2 = 0xff;
  return;
}

