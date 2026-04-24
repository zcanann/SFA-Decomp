// Function: FUN_800550d0
// Entry: 800550d0
// Size: 96 bytes

void FUN_800550d0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6)

{
  if (param_3 < 0) {
    param_3 = 0;
  }
  if (param_4 < 0) {
    param_4 = 0;
  }
  if (param_5 < 0) {
    param_5 = 0;
  }
  if (param_6 < 0) {
    param_6 = 0;
  }
  FUN_8025d324(param_3,param_4,param_5 - param_3,param_6 - param_4);
  return;
}

