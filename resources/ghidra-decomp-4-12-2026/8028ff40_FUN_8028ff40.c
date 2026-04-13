// Function: FUN_8028ff40
// Entry: 8028ff40
// Size: 124 bytes

int FUN_8028ff40(char *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_80292020(-0x7fcccfd0,-1);
  if (iVar1 < 0) {
    iVar1 = FUN_80290080(FUN_80290028,&DAT_80333030,param_1,param_2);
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

