// Function: FUN_802237d4
// Entry: 802237d4
// Size: 96 bytes

void FUN_802237d4(int param_1)

{
  uint *puVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0xa0) == 0x203) {
    puVar1 = FUN_80039598();
    FUN_8003abd8(param_1,puVar1,(uint)*(byte *)(iVar2 + 0x610),0,100000);
  }
  return;
}

