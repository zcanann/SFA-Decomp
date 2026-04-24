// Function: FUN_80114db8
// Entry: 80114db8
// Size: 148 bytes

void FUN_80114db8(int param_1)

{
  uint *puVar1;
  int iVar2;
  
  puVar1 = FUN_80039598();
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6d0 + 0x48))(0);
  *(undefined *)(iVar2 + 0x600) = 0;
  FUN_8003adf4(param_1,puVar1,(uint)*(byte *)(iVar2 + 0x610),iVar2 + 0x1c);
  *(undefined4 *)(iVar2 + 0x5f8) = 0x50;
  FUN_8003aab8(iVar2 + 0x1c,(uint)*(byte *)(iVar2 + 0x610),0,0);
  return;
}

