// Function: FUN_801142b4
// Entry: 801142b4
// Size: 108 bytes

double FUN_801142b4(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  double dVar2;
  
  iVar1 = (**(code **)(*DAT_803dd71c + 0x40))(param_2);
  if (iVar1 < 0) {
    dVar2 = (double)FLOAT_803e2908;
  }
  else {
    dVar2 = (double)(**(code **)(*DAT_803dd71c + 0x24))(param_1);
  }
  return dVar2;
}

