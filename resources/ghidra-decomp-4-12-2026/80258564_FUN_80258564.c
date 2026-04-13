// Function: FUN_80258564
// Entry: 80258564
// Size: 116 bytes

void FUN_80258564(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = 9;
  do {
    *param_2 = iVar1;
    FUN_8025831c(param_1,iVar1,(uint *)(param_2 + 1),(uint *)(param_2 + 2),(byte *)(param_2 + 3));
    iVar1 = iVar1 + 1;
    param_2 = param_2 + 4;
  } while (iVar1 < 0x1a);
  *param_2 = 0xff;
  return;
}

