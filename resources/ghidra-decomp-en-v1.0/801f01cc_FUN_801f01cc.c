// Function: FUN_801f01cc
// Entry: 801f01cc
// Size: 96 bytes

void FUN_801f01cc(int param_1,int param_2)

{
  if (*(short *)(param_1 + 0x46) != 0x188) {
    if ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\0') && (param_2 == 0)) {
      *(undefined *)(*(int *)(param_1 + 0xb8) + 0xc) = 0;
    }
    if (DAT_803ddc74 != 0) {
      FUN_80013e2c();
      DAT_803ddc74 = 0;
    }
  }
  return;
}

