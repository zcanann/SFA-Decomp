// Function: FUN_8024c478
// Entry: 8024c478
// Size: 1144 bytes

void FUN_8024c478(void)

{
  ushort *puVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short sVar7;
  int iVar6;
  short sVar8;
  uint uVar9;
  
  DAT_803ddf78 = 1;
  uVar2 = read_volatile_2(DAT_cc002002);
  if ((uVar2 & 1) == 0) {
    FUN_8024c280(0);
  }
  DAT_803ddf60 = 0;
  DAT_803ddf8c = 0;
  DAT_803ddf88 = 0;
  DAT_803ddf9c = 0;
  DAT_803ddf98 = 0;
  DAT_803ddf80 = 0;
  DAT_803ddf90 = 0;
  DAT_803ddf64 = 0;
  write_volatile_2(DAT_cc00204e,DAT_8032df20 | DAT_8032df22 << 10);
  write_volatile_2(DAT_cc00204c,(ushort)((int)(uint)DAT_8032df22 >> 6) | DAT_8032df24 << 4);
  write_volatile_2(DAT_cc002052,DAT_8032df26 | DAT_8032df28 << 10);
  write_volatile_2(DAT_cc002050,(ushort)((int)(uint)DAT_8032df28 >> 6) | DAT_8032df2a << 4);
  write_volatile_2(DAT_cc002056,DAT_8032df2c | DAT_8032df2e << 10);
  write_volatile_2(DAT_cc002054,(ushort)((int)(uint)DAT_8032df2e >> 6) | DAT_8032df30 << 4);
  write_volatile_2(DAT_cc00205a,DAT_8032df32 | DAT_8032df34 << 8);
  write_volatile_2(DAT_cc002058,DAT_8032df36 | DAT_8032df38 << 8);
  write_volatile_2(DAT_cc00205e,DAT_8032df3a | DAT_8032df3c << 8);
  write_volatile_2(DAT_cc00205c,DAT_8032df3e | DAT_8032df40 << 8);
  write_volatile_2(DAT_cc002062,DAT_8032df42 | DAT_8032df44 << 8);
  write_volatile_2(DAT_cc002060,DAT_8032df46 | DAT_8032df48 << 8);
  write_volatile_2(DAT_cc002066,DAT_8032df4a | DAT_8032df4c << 8);
  write_volatile_2(DAT_cc002064,DAT_8032df4e | DAT_8032df50 << 8);
  write_volatile_2(DAT_cc002070,0x280);
  iVar3 = FUN_80245188();
  DAT_803ddf7e = 0;
  DAT_803ddf7c = (short)*(char *)(iVar3 + 0x10);
  FUN_80245548(0);
  uVar2 = read_volatile_2(DAT_cc002002);
  DAT_803ae17c = uVar2 >> 2 & 1;
  DAT_803ae180 = uVar2 >> 8 & 3;
  uVar9 = DAT_803ae180;
  if (DAT_803ae180 == 3) {
    uVar9 = 0;
  }
  DAT_803ae1ac = FUN_8024c1f0(uVar9 * 4 + DAT_803ae17c);
  DAT_803ddfa4 = DAT_803ae180;
  DAT_803ae15c = 0x280;
  puVar1 = (ushort *)(DAT_803ae1ac + 2);
  DAT_803ae15e = *puVar1 * 2;
  DAT_803ae158 = 0x28;
  DAT_803ae15a = 0;
  DAT_803ae160 = 0x50;
  iVar3 = DAT_803ddf7c + 0x28;
  if (iVar3 < 0x51) {
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    DAT_803ae160 = (undefined2)iVar3;
  }
  if (DAT_803ae178 == 0) {
    iVar3 = 2;
  }
  else {
    iVar3 = 1;
  }
  iVar4 = (int)DAT_803ddf7e;
  DAT_803ae162 = 0;
  if (0 < iVar4) {
    DAT_803ae162 = DAT_803ddf7e;
  }
  iVar5 = (int)(short)*puVar1;
  if (DAT_803ae15e + iVar4 + iVar5 * -2 < 1) {
    sVar8 = 0;
  }
  else {
    sVar8 = (short)(DAT_803ae15e + iVar4) + *puVar1 * -2;
  }
  sVar7 = DAT_803ddf7e;
  if (-1 < iVar4) {
    sVar7 = 0;
  }
  DAT_803ae164 = (DAT_803ae15e + sVar7) - sVar8;
  iVar6 = iVar4;
  if (-1 < iVar4) {
    iVar6 = 0;
  }
  DAT_803ae166 = DAT_803ae170 - (short)(iVar6 / iVar3);
  if (DAT_803ae15e + iVar4 + iVar5 * -2 < 1) {
    iVar5 = 0;
  }
  else {
    iVar5 = DAT_803ae15e + iVar4 + iVar5 * -2;
  }
  if (-1 < iVar4) {
    iVar4 = 0;
  }
  DAT_803ae168 = (DAT_803ae174 + (short)(iVar4 / iVar3)) - (short)(iVar5 / iVar3);
  DAT_803ae16a = 0x280;
  DAT_803ae16c = (undefined2)((*puVar1 & 0x7fff) << 1);
  DAT_803ae16e = 0;
  DAT_803ae170 = 0;
  DAT_803ae172 = 0x280;
  DAT_803ae174 = (short)((*puVar1 & 0x7fff) << 1);
  DAT_803ae178 = 0;
  DAT_803ae184 = 0x28;
  DAT_803ae185 = 0x28;
  DAT_803ae186 = 0x28;
  DAT_803ae194 = 0;
  DAT_803ae198 = 1;
  DAT_803ae19c = 0;
  DAT_803ae06a = uVar2;
  DAT_803ddfa0 = DAT_803ae1ac;
  FUN_80245d78(&DAT_803ddf68);
  uVar2 = read_volatile_2(DAT_cc002030);
  write_volatile_2(DAT_cc002030,uVar2 & 0x7fff);
  uVar2 = read_volatile_2(DAT_cc002034);
  write_volatile_2(DAT_cc002034,uVar2 & 0x7fff);
  DAT_803ddf70 = 0;
  DAT_803ddf74 = 0;
  FUN_802437c8(0x18,&LAB_8024bf40);
  FUN_80243bcc(0x80);
  return;
}

