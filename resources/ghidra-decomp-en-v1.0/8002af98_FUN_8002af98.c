// Function: FUN_8002af98
// Entry: 8002af98
// Size: 172 bytes

void FUN_8002af98(int param_1)

{
  *(undefined2 *)(param_1 + 0xe6) = 0;
  *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) & 0xfe;
  *(undefined *)(param_1 + 0xf0) = 0;
  FUN_8002843c(*(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4));
  (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7fb,0,0x50,0);
  (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7fc,0,0x32,0);
  return;
}

