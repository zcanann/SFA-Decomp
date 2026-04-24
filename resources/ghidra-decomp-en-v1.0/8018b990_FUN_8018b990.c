// Function: FUN_8018b990
// Entry: 8018b990
// Size: 96 bytes

void FUN_8018b990(short *param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  FUN_80037200(param_1,0x1e);
  *piVar1 = (uint)*(byte *)(param_2 + 0x19) * 0x3c;
  *param_1 = (short)*(char *)(param_2 + 0x18);
  return;
}

