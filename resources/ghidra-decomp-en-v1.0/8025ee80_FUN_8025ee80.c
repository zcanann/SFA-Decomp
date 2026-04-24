// Function: FUN_8025ee80
// Entry: 8025ee80
// Size: 100 bytes

int FUN_8025ee80(int *param_1,int param_2)

{
  FUN_8024377c();
  if (*param_1 == 0) {
    if (param_1[1] == -1) {
      param_1[1] = param_2;
    }
  }
  else {
    param_1[1] = param_2;
  }
  FUN_802437a4();
  return param_2;
}

