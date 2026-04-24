// Function: FUN_80212918
// Entry: 80212918
// Size: 260 bytes

undefined4 FUN_80212918(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if ((*(char *)(param_2 + 0x346) != '\0') || ((*(ushort *)(DAT_803ddd54 + 0xfa) & 8) != 0)) {
      return 9;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,6);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(char *)(DAT_803ddd54 + 0x101) = *(char *)(DAT_803ddd54 + 0x101) + '\x01';
    FUN_80211cd8();
    FUN_800200e8(0x572,*(undefined *)(DAT_803ddd54 + 0x101));
    *(ushort *)(DAT_803ddd54 + 0xfa) = *(ushort *)(DAT_803ddd54 + 0xfa) | 0x10;
    *(ushort *)(DAT_803ddd54 + 0xfa) = *(ushort *)(DAT_803ddd54 + 0xfa) & 0xfff7;
    FUN_8000a518(0x94,0);
    FUN_8000a518(0x28,0);
    FUN_8000a518(0x93,1);
  }
  return 0;
}

