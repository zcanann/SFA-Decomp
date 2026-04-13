// Function: FUN_80210178
// Entry: 80210178
// Size: 44 bytes

void FUN_80210178(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
  }
  return;
}

