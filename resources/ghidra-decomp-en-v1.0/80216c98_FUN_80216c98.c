// Function: FUN_80216c98
// Entry: 80216c98
// Size: 120 bytes

void FUN_80216c98(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_8001f4c8(0,1);
  *(undefined4 *)(iVar2 + 4) = uVar1;
  if (*(int *)(iVar2 + 4) != 0) {
    FUN_8001db2c(*(int *)(iVar2 + 4),2);
    FUN_8001dd88((double)*(float *)(param_2 + 8),(double)*(float *)(param_2 + 0xc),
                 (double)*(float *)(param_2 + 0x10),*(undefined4 *)(iVar2 + 4));
    FUN_8001dd40(*(undefined4 *)(iVar2 + 4),1);
  }
  return;
}

