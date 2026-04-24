// Function: FUN_800d86ac
// Entry: 800d86ac
// Size: 268 bytes

void FUN_800d86ac(undefined4 param_1,undefined4 param_2,short param_3,int param_4,undefined4 param_5
                 ,int param_6)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_80013ec8(param_3 + 0x58,1);
  for (; param_4 != 0; param_4 = param_4 + -1) {
    if (param_6 == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,1,0xffffffff,0);
    }
    else if (param_6 == 1) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,2,0xffffffff,0);
    }
    else if (param_6 == 2) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,4,0xffffffff,0);
    }
  }
  FUN_80013e2c(piVar1);
  return;
}

