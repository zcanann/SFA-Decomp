// Function: FUN_80094734
// Entry: 80094734
// Size: 172 bytes

void FUN_80094734(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  if (DAT_8039b788 != 0) {
    param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           DAT_8039b788);
    DAT_8039b788 = 0;
  }
  DAT_8039b794 = 0;
  if (DAT_8039b78c != 0) {
    param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           DAT_8039b78c);
    DAT_8039b78c = 0;
  }
  DAT_8039b798 = 0;
  if (DAT_8039b790 != 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_8039b790);
    DAT_8039b790 = 0;
  }
  DAT_8039b79c = 0;
  return;
}

