// Function: FUN_8002cf80
// Entry: 8002cf80
// Size: 56 bytes

void FUN_8002cf80(int param_1)

{
  if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
    FUN_80013abc((short *)&DAT_803dd7fc,param_1);
  }
  return;
}

