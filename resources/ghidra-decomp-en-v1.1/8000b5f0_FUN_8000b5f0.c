// Function: FUN_8000b5f0
// Entry: 8000b5f0
// Size: 84 bytes

bool FUN_8000b5f0(int param_1,short param_2)

{
  int *piVar1;
  
  if (param_2 == 0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_8000cd0c(param_1,0,param_2,0);
  }
  return piVar1 != (int *)0x0;
}

