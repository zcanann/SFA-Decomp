// Function: FUN_8000b5d0
// Entry: 8000b5d0
// Size: 84 bytes

bool FUN_8000b5d0(undefined4 param_1,uint param_2)

{
  int iVar1;
  
  if ((param_2 & 0xffff) == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_8000ccec(param_1,0,param_2,0);
  }
  return iVar1 != 0;
}

