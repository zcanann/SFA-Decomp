// Function: FUN_80242394
// Entry: 80242394
// Size: 216 bytes

undefined8 FUN_80242394(int param_1)

{
  uint in_MSR;
  
  if ((0x8024377b < *(uint *)(param_1 + 0x198)) && (*(uint *)(param_1 + 0x198) < 0x8024378d)) {
    *(code **)(param_1 + 0x198) = FUN_8024377c;
  }
  if ((*(ushort *)(param_1 + 0x1a2) & 2) != 0) {
    *(ushort *)(param_1 + 0x1a2) = *(ushort *)(param_1 + 0x1a2) & 0xfffd;
  }
  returnFromInterrupt(in_MSR & 0x9000,*(undefined4 *)(param_1 + 0x19c));
  return *(undefined8 *)(param_1 + 0xc);
}

