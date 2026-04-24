// Function: FUN_8024c280
// Entry: 8024c280
// Size: 504 bytes

void FUN_8024c280(uint param_1)

{
  uint uVar1;
  byte *pbVar2;
  uint local_14;
  
  uVar1 = param_1 >> 2;
  DAT_800000cc = uVar1;
  pbVar2 = (byte *)FUN_8024c1f0(param_1);
  write_volatile_2(DAT_cc002002,2);
  for (local_14 = 0; local_14 < 1000; local_14 = local_14 + 8) {
  }
  write_volatile_2(DAT_cc002002,0);
  write_volatile_2(DAT_cc002006,*(undefined2 *)(pbVar2 + 0x1a));
  write_volatile_2(DAT_cc002004,*(undefined2 *)(pbVar2 + 0x1d));
  write_volatile_2(DAT_cc00200a,(ushort)pbVar2[0x1c] | (ushort)pbVar2[0x1f] << 7);
  write_volatile_2(DAT_cc002008,*(short *)(pbVar2 + 0x20) << 1);
  write_volatile_2(DAT_cc002000,(ushort)*pbVar2);
  write_volatile_2(DAT_cc00200e,*(short *)(pbVar2 + 4) + *(short *)(pbVar2 + 2) * 2 + -2);
  write_volatile_2(DAT_cc00200c,*(short *)(pbVar2 + 8) + 2);
  write_volatile_2(DAT_cc002012,*(short *)(pbVar2 + 6) + *(short *)(pbVar2 + 2) * 2 + -2);
  write_volatile_2(DAT_cc002010,*(short *)(pbVar2 + 10) + 2);
  write_volatile_2(DAT_cc002016,(ushort)pbVar2[0xc] | *(short *)(pbVar2 + 0x10) << 5);
  write_volatile_2(DAT_cc002014,(ushort)pbVar2[0xe] | *(short *)(pbVar2 + 0x14) << 5);
  write_volatile_2(DAT_cc00201a,(ushort)pbVar2[0xd] | *(short *)(pbVar2 + 0x12) << 5);
  write_volatile_2(DAT_cc002018,(ushort)pbVar2[0xf] | *(short *)(pbVar2 + 0x16) << 5);
  write_volatile_2(DAT_cc002048,0x2828);
  write_volatile_2(DAT_cc002036,1);
  write_volatile_2(DAT_cc002034,0x1001);
  write_volatile_2(DAT_cc002032,*(short *)(pbVar2 + 0x1a) + 1);
  write_volatile_2(DAT_cc002030,(short)((int)(uint)*(ushort *)(pbVar2 + 0x18) >> 1) + 1U | 0x1000);
  if ((param_1 == 2) || (param_1 == 3)) {
    write_volatile_2(DAT_cc002002,(ushort)(uVar1 << 8) | 5);
    write_volatile_2(DAT_cc00206c,1);
  }
  else {
    write_volatile_2(DAT_cc002002,(ushort)((param_1 & 2) << 2) | 1 | (ushort)(uVar1 << 8));
    write_volatile_2(DAT_cc00206c,0);
  }
  return;
}

