// Function: FUN_801927e4
// Entry: 801927e4
// Size: 116 bytes

void FUN_801927e4(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x11) = *(undefined *)(param_2 + 0x1e);
  *(undefined *)(iVar1 + 0x12) = *(undefined *)(param_2 + 0x1f);
  *(undefined *)(iVar1 + 0x13) = *(undefined *)(param_2 + 0x1c);
  *(undefined *)(iVar1 + 0x14) = *(undefined *)(param_2 + 0x1d);
  if (param_3 == 0) {
    FUN_801924d0();
  }
  *(int *)(iVar1 + 8) = (int)*(short *)(param_2 + 0x1a);
  *(undefined4 *)(iVar1 + 0xc) = 0xffffffff;
  return;
}

