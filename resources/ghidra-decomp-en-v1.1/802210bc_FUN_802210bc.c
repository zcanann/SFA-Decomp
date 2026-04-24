// Function: FUN_802210bc
// Entry: 802210bc
// Size: 52 bytes

void FUN_802210bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  if ((*(byte *)(*(int *)(param_9 + 0xb8) + 4) >> 6 & 1) != 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

