// Function: FUN_80003514
// Entry: 80003514
// Size: 36 bytes

void FUN_80003514(int param_1,int param_2,int param_3)

{
  undefined *puVar1;
  int iVar2;
  undefined *puVar3;
  
  puVar1 = (undefined *)(param_2 + -1);
  puVar3 = (undefined *)(param_1 + -1);
  iVar2 = param_3 + 1;
  while( true ) {
    iVar2 = iVar2 + -1;
    if (iVar2 == 0) break;
    puVar1 = puVar1 + 1;
    puVar3 = puVar3 + 1;
    *puVar3 = *puVar1;
  }
  return;
}

