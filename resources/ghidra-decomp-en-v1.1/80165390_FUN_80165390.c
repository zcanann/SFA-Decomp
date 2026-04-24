// Function: FUN_80165390
// Entry: 80165390
// Size: 72 bytes

void FUN_80165390(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  if (param_9[0x23] == 0x39d) {
    FUN_80164dec(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    FUN_8016465c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  FUN_801650f0((uint)param_9);
  return;
}

