// Function: FUN_80296a9c
// Entry: 80296a9c
// Size: 56 bytes

void FUN_80296a9c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
  param_2 = *(short *)(iVar1 + 6) + param_2;
  if (param_2 < 0) {
    param_2 = 0;
  }
  else if (100 < param_2) {
    param_2 = 100;
  }
  *(short *)(iVar1 + 6) = (short)param_2;
  return;
}

