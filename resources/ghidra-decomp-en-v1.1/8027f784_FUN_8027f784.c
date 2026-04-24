// Function: FUN_8027f784
// Entry: 8027f784
// Size: 168 bytes

undefined4 FUN_8027f784(int param_1,byte *param_2)

{
  if (*(byte *)(param_1 + 0x52) < 7) {
    *(byte *)(param_1 + (uint)*(byte *)(param_1 + 0x52) * 0xc + 0x58) = param_2[3];
    *(ushort *)(param_1 + (uint)*(byte *)(param_1 + 0x52) * 0xc + 0x5a) =
         (ushort)*param_2 << 8 | (ushort)*param_2 << 1;
    *(ushort *)(param_1 + (uint)*(byte *)(param_1 + 0x52) * 0xc + 0x5c) =
         (ushort)param_2[1] << 8 | (ushort)param_2[1] << 1;
    *(ushort *)(param_1 + (uint)*(byte *)(param_1 + 0x52) * 0xc + 0x5e) =
         (ushort)param_2[2] << 8 | (ushort)param_2[2] << 1;
    *(byte **)(param_1 + (uint)*(byte *)(param_1 + 0x52) * 0xc + 0x60) = param_2;
    *(char *)(param_1 + 0x52) = *(char *)(param_1 + 0x52) + '\x01';
    return 1;
  }
  return 0;
}

