// Function: FUN_800d9dcc
// Entry: 800d9dcc
// Size: 128 bytes

void FUN_800d9dcc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  
  cVar1 = FUN_80014054();
  if (cVar1 != '\0') {
    FUN_800140bc(param_1);
  }
  FUN_80014060(param_1);
  (**(code **)(*DAT_803dca68 + 0xc))(param_1,param_2,param_3);
  return;
}

