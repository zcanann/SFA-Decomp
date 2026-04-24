// Function: FUN_8005b068
// Entry: 8005b068
// Size: 44 bytes

undefined4 FUN_8005b068(int param_1)

{
  if ((-1 < param_1) && (param_1 < (int)(uint)DAT_803ddb18)) {
    return *(undefined4 *)(DAT_803ddb1c + param_1 * 4);
  }
  return 0;
}

