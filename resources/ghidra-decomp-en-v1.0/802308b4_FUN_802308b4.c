// Function: FUN_802308b4
// Entry: 802308b4
// Size: 80 bytes

void FUN_802308b4(int param_1)

{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 0x1b) == '\0') {
    FUN_8000a518(2,1);
  }
  else {
    FUN_8000a518(0xf3,1);
  }
  FUN_8011f354(1);
  return;
}

