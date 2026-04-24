// Function: FUN_80003514
// Entry: 80003514
// Size: 36 bytes

void FUN_80003514(int param_1,int param_2,int param_3)

{
  undefined *puVar1;
  undefined *puVar2;
  
  puVar1 = (undefined *)(param_2 + -1);
  puVar2 = (undefined *)(param_1 + -1);
  param_3 = param_3 + 1;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 == 0) break;
    puVar1 = puVar1 + 1;
    puVar2 = puVar2 + 1;
    *puVar2 = *puVar1;
  }
  return;
}

