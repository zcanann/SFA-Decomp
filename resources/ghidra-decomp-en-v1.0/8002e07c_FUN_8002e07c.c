// Function: FUN_8002e07c
// Entry: 8002e07c
// Size: 56 bytes

int FUN_8002e07c(int param_1)

{
  if ((-1 < param_1) && (param_1 < DAT_803dcbac)) {
    return DAT_803dcbb4 + *(int *)(DAT_803dcbb0 + param_1 * 4) * 4;
  }
  return DAT_803dcbb4;
}

