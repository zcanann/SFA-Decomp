// Function: FUN_80143b04
// Entry: 80143b04
// Size: 116 bytes

undefined4 FUN_80143b04(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_8014460c();
  if (((iVar1 == 0) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) &&
     (*(int *)(param_2 + 0x20) == (int)*(short *)(param_1 + 0xa0))) {
    *(undefined *)(param_2 + 10) = 0;
  }
  return 1;
}

