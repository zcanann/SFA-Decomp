// Function: FUN_8000b578
// Entry: 8000b578
// Size: 88 bytes

bool FUN_8000b578(int param_1,uint param_2)

{
  int iVar1;
  
  if (((param_2 & 0xff) == 0) || (param_1 == 0)) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_8000ccec(param_1,param_2,0,0);
  }
  return iVar1 != 0;
}

