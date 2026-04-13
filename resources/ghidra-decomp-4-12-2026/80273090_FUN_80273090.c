// Function: FUN_80273090
// Entry: 80273090
// Size: 68 bytes

uint FUN_80273090(uint param_1)

{
  int iVar1;
  
  iVar1 = FUN_80279c00(param_1);
  if (iVar1 == -1) {
    param_1 = 0xffffffff;
  }
  return param_1;
}

