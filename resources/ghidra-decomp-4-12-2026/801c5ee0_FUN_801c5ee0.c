// Function: FUN_801c5ee0
// Entry: 801c5ee0
// Size: 92 bytes

void FUN_801c5ee0(int param_1,int param_2)

{
  FUN_80036018(param_1);
  *(undefined4 *)(param_1 + 0xf4) = 0;
  *(uint *)(param_1 + 0xf8) =
       CONCAT22(*(undefined2 *)(param_2 + 0x1c),*(undefined2 *)(param_2 + 0x1a));
  return;
}

