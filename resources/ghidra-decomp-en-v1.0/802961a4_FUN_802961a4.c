// Function: FUN_802961a4
// Entry: 802961a4
// Size: 48 bytes

void FUN_802961a4(int param_1,int *param_2,undefined4 *param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = (int)*(short *)(param_1 + 0xa0);
  if (*(short *)(iVar1 + 0x274) == 0x26) {
    *param_3 = *(undefined4 *)(iVar1 + 0x7d8);
    return;
  }
  *param_3 = *(undefined4 *)(iVar1 + 0x7d4);
  return;
}

