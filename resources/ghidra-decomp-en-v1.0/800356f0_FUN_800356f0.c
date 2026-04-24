// Function: FUN_800356f0
// Entry: 800356f0
// Size: 132 bytes

int FUN_800356f0(int param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = FUN_80022e24(param_2);
  *(int *)(param_1 + 0x58) = iVar1;
  if (*(int *)(param_1 + 0x58) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x58) + 0x10c) = 0;
    *(undefined *)(*(int *)(param_1 + 0x58) + 0x10d) = 10;
    *(undefined *)(*(int *)(param_1 + 0x58) + 0x10f) = 0;
    FUN_80032410(param_1,1);
    FUN_80032410(param_1,1);
  }
  return iVar1 + 0x110;
}

