// Function: FUN_80263590
// Entry: 80263590
// Size: 48 bytes

undefined4 FUN_80263590(char *param_1)

{
  if (*param_1 == -1) {
    return 0xfffffffc;
  }
  if ((param_1[0x34] & 4U) != 0) {
    return 0;
  }
  return 0xfffffff6;
}

