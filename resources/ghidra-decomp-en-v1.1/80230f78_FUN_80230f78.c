// Function: FUN_80230f78
// Entry: 80230f78
// Size: 80 bytes

void FUN_80230f78(int param_1)

{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 0x1b) == '\0') {
    FUN_8000a538((int *)0x2,1);
  }
  else {
    FUN_8000a538((int *)0xf3,1);
  }
  FUN_8011f638(1);
  return;
}

