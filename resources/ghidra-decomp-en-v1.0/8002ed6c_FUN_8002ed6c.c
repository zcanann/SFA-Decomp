// Function: FUN_8002ed6c
// Entry: 8002ed6c
// Size: 84 bytes

void FUN_8002ed6c(int param_1,undefined4 param_2,short param_3)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  iVar1 = *piVar2;
  if (*(short *)(iVar1 + 0xec) != 0) {
    FUN_8002eb54(param_1,iVar1,piVar2[0xb],param_2,(int)param_3);
  }
  return;
}

