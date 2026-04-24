// Function: FUN_80262e2c
// Entry: 80262e2c
// Size: 48 bytes

undefined4 FUN_80262e2c(char *param_1)

{
  if (*param_1 == -1) {
    return 0xfffffffc;
  }
  if ((param_1[0x34] & 4U) != 0) {
    return 0;
  }
  return 0xfffffff6;
}

