// Function: FUN_8000b598
// Entry: 8000b598
// Size: 88 bytes

bool FUN_8000b598(int param_1,ushort param_2)

{
  int *piVar1;
  
  if (((param_2 & 0xff) == 0) || (param_1 == 0)) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_8000cd0c(param_1,param_2,0,0);
  }
  return piVar1 != (int *)0x0;
}

