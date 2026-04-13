// Function: FUN_80102354
// Entry: 80102354
// Size: 84 bytes

void FUN_80102354(int param_1,int param_2)

{
  if (*(char *)(DAT_803de19c + 0x13b) < param_1) {
    *(char *)(DAT_803de19c + 0x13b) = (char)param_1;
    *(undefined *)(DAT_803de19c + 0x13c) = 2;
    if (param_2 != 0) {
      FUN_8000fb0c((short)param_1);
    }
  }
  return;
}

