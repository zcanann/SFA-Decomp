// Function: FUN_8021fa38
// Entry: 8021fa38
// Size: 124 bytes

void FUN_8021fa38(int param_1)

{
  if ((*(ushort *)(param_1 + 0xb0) & 0x200) == 0) {
    FUN_8002cbc4();
  }
  else {
    FUN_80035f00();
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) & 0xfdff;
    FUN_8002ce88(param_1);
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

