// Function: FUN_800805ec
// Entry: 800805ec
// Size: 36 bytes

undefined4 FUN_800805ec(int param_1,undefined2 param_2)

{
  *(undefined2 *)(&DAT_8030f8b8 + *(char *)(param_1 + 0x57) * 2) = param_2;
  return 1;
}

