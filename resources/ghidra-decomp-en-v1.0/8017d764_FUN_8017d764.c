// Function: FUN_8017d764
// Entry: 8017d764
// Size: 172 bytes

void FUN_8017d764(short *param_1,int param_2)

{
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  (**(code **)(*DAT_803dcac0 + 4))(param_1,*(undefined4 *)(param_1 + 0x5c),0x32);
  FUN_80037200(param_1,4);
  return;
}

