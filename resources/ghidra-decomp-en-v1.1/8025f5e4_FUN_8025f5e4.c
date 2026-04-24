// Function: FUN_8025f5e4
// Entry: 8025f5e4
// Size: 100 bytes

int FUN_8025f5e4(int *param_1,int param_2)

{
  FUN_80243e74();
  if (*param_1 == 0) {
    if (param_1[1] == -1) {
      param_1[1] = param_2;
    }
  }
  else {
    param_1[1] = param_2;
  }
  FUN_80243e9c();
  return param_2;
}

