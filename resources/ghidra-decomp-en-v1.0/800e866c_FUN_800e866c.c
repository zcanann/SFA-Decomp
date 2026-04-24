// Function: FUN_800e866c
// Entry: 800e866c
// Size: 100 bytes

void FUN_800e866c(void)

{
  FUN_80244760(0,0);
  DAT_803db890 = (undefined)((int)(*(byte *)(DAT_803dd498 + 0x21) & 0x60) >> 5);
  *(byte *)(DAT_803dd498 + 0x21) = *(byte *)(DAT_803dd498 + 0x21) & 0x1f;
  (**(code **)(*DAT_803dcaac + 0x20))();
  return;
}

