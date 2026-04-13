// Function: FUN_802971fc
// Entry: 802971fc
// Size: 56 bytes

void FUN_802971fc(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
  iVar1 = *(short *)(iVar2 + 6) + param_2;
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  else if (100 < iVar1) {
    iVar1 = 100;
  }
  *(short *)(iVar2 + 6) = (short)iVar1;
  return;
}

