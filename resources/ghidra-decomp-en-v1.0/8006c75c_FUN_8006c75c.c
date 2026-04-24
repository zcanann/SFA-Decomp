// Function: FUN_8006c75c
// Entry: 8006c75c
// Size: 76 bytes

void FUN_8006c75c(undefined4 param_1)

{
  if (*(char *)(DAT_803dcfe4 + 0x48) == '\0') {
    FUN_8025a8f0(DAT_803dcfe4 + 0x20,param_1);
  }
  else {
    FUN_8025a748(DAT_803dcfe4 + 0x20,*(undefined4 *)(DAT_803dcfe4 + 0x40));
  }
  return;
}

