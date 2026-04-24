// Function: FUN_8006c6a4
// Entry: 8006c6a4
// Size: 76 bytes

void FUN_8006c6a4(undefined4 param_1)

{
  if (*(char *)(DAT_803dcfcc + 0x48) == '\0') {
    FUN_8025a8f0(DAT_803dcfcc + 0x20,param_1);
  }
  else {
    FUN_8025a748(DAT_803dcfcc + 0x20,*(undefined4 *)(DAT_803dcfcc + 0x40));
  }
  return;
}

