// Function: FUN_80248ea8
// Entry: 80248ea8
// Size: 188 bytes

void FUN_80248ea8(void)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  
  DAT_cc006004 = 2;
  uVar2 = DAT_cc003024;
  DAT_cc003024 = uVar2 & 0xfffffffb | 1;
  lVar3 = FUN_802473d4();
  uVar1 = DAT_800000f8 / 500000;
  do {
    lVar4 = FUN_802473d4();
  } while (((int)((ulonglong)lVar4 >> 0x20) -
            ((uint)((uint)lVar4 < (uint)lVar3) + (int)((ulonglong)lVar3 >> 0x20)) ^ 0x80000000) <
           ((uint)lVar4 - (uint)lVar3 < uVar1 * 0xc >> 3) + 0x80000000);
  DAT_cc003024 = uVar2 | 5;
  DAT_803deb38 = 1;
  lVar3 = FUN_802473d4();
  DAT_803deb34 = (int)lVar3;
  DAT_803deb30 = (int)((ulonglong)lVar3 >> 0x20);
  return;
}

