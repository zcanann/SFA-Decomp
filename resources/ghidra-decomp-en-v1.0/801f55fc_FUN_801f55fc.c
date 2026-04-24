// Function: FUN_801f55fc
// Entry: 801f55fc
// Size: 136 bytes

void FUN_801f55fc(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_801f4c28(param_1,iVar1);
  *(undefined *)(param_1 + 0x36) = 0;
  *(code **)(param_1 + 0xbc) = FUN_801f4c04;
  FUN_80037964(param_1,1);
  FUN_8008016c(iVar1 + 0x74);
  if (*(short *)(param_2 + 0x1a) == 0x7f) {
    FUN_80080178(iVar1 + 0x74,0xe10);
  }
  return;
}

