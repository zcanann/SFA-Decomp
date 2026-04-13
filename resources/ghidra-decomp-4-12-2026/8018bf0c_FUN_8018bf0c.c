// Function: FUN_8018bf0c
// Entry: 8018bf0c
// Size: 96 bytes

void FUN_8018bf0c(short *param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,0x1e);
  *piVar1 = (uint)*(byte *)(param_2 + 0x19) * 0x3c;
  *param_1 = (short)*(char *)(param_2 + 0x18);
  return;
}

