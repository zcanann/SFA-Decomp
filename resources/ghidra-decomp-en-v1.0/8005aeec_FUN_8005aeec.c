// Function: FUN_8005aeec
// Entry: 8005aeec
// Size: 44 bytes

undefined4 FUN_8005aeec(int param_1)

{
  if ((-1 < param_1) && (param_1 < (int)(uint)DAT_803dce98)) {
    return *(undefined4 *)(DAT_803dce9c + param_1 * 4);
  }
  return 0;
}

