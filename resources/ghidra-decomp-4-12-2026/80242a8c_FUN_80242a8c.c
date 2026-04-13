// Function: FUN_80242a8c
// Entry: 80242a8c
// Size: 216 bytes

undefined8 FUN_80242a8c(int param_1)

{
  uint in_MSR;
  
  if ((0x80243e73 < *(uint *)(param_1 + 0x198)) && (*(uint *)(param_1 + 0x198) < 0x80243e85)) {
    *(code **)(param_1 + 0x198) = FUN_80243e74;
  }
  if ((*(ushort *)(param_1 + 0x1a2) & 2) != 0) {
    *(ushort *)(param_1 + 0x1a2) = *(ushort *)(param_1 + 0x1a2) & 0xfffd;
  }
  returnFromInterrupt(in_MSR & 0x9000,*(undefined4 *)(param_1 + 0x19c));
  return *(undefined8 *)(param_1 + 0xc);
}

