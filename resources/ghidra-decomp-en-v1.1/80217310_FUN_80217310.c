// Function: FUN_80217310
// Entry: 80217310
// Size: 120 bytes

void FUN_80217310(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  piVar1 = FUN_8001f58c(0,'\x01');
  *(int **)(iVar2 + 4) = piVar1;
  if (*(int *)(iVar2 + 4) != 0) {
    FUN_8001dbf0(*(int *)(iVar2 + 4),2);
    FUN_8001de4c((double)*(float *)(param_2 + 8),(double)*(float *)(param_2 + 0xc),
                 (double)*(float *)(param_2 + 0x10),*(int **)(iVar2 + 4));
    FUN_8001de04(*(int *)(iVar2 + 4),1);
  }
  return;
}

