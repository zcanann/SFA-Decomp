// Function: FUN_80080360
// Entry: 80080360
// Size: 36 bytes

undefined4 FUN_80080360(int param_1,undefined2 param_2)

{
  *(undefined2 *)(&DAT_8030ecf8 + *(char *)(param_1 + 0x57) * 2) = param_2;
  return 1;
}

