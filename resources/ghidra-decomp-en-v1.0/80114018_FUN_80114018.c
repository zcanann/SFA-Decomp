// Function: FUN_80114018
// Entry: 80114018
// Size: 108 bytes

double FUN_80114018(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  double dVar2;
  
  iVar1 = (**(code **)(*DAT_803dca9c + 0x40))(param_2);
  if (iVar1 < 0) {
    dVar2 = (double)FLOAT_803e1c88;
  }
  else {
    dVar2 = (double)(**(code **)(*DAT_803dca9c + 0x24))(param_1);
  }
  return dVar2;
}

