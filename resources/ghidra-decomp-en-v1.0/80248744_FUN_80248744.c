// Function: FUN_80248744
// Entry: 80248744
// Size: 188 bytes

void FUN_80248744(void)

{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  write_volatile_4(DAT_cc006004,2);
  uVar2 = read_volatile_4(DAT_cc003024);
  write_volatile_4(DAT_cc003024,uVar2 & 0xfffffffb | 1);
  uVar3 = FUN_80246c70();
  uVar1 = DAT_800000f8 >> 2;
  do {
    uVar4 = FUN_80246c70();
  } while (((int)((ulonglong)uVar4 >> 0x20) -
            ((uint)((uint)uVar4 < (uint)uVar3) + (int)((ulonglong)uVar3 >> 0x20)) ^ 0x80000000) <
           ((uint)uVar4 - (uint)uVar3 < (uVar1 / 0x1e848) * 0xc >> 3) + 0x80000000);
  write_volatile_4(DAT_cc003024,uVar2 | 5);
  DAT_803ddeb8 = 1;
  uVar3 = FUN_80246c70();
  DAT_803ddeb0 = (int)((ulonglong)uVar3 >> 0x20);
  DAT_803ddeb4 = (int)uVar3;
  return;
}

