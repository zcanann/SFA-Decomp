// Function: FUN_8002b070
// Entry: 8002b070
// Size: 172 bytes

void FUN_8002b070(int param_1)

{
  *(undefined2 *)(param_1 + 0xe6) = 0;
  *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) & 0xfe;
  *(undefined *)(param_1 + 0xf0) = 0;
  FUN_80028500(*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4));
  (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7fb,0,0x50,0);
  (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7fc,0,0x32,0);
  return;
}

