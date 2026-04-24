// Function: FUN_801964b4
// Entry: 801964b4
// Size: 100 bytes

void FUN_801964b4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x32));
  *(bool *)(iVar2 + 2) = iVar1 != 0;
  FUN_80037200(param_1,0x1a);
  return;
}

