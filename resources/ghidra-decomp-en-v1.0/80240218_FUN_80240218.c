// Function: FUN_80240218
// Entry: 80240218
// Size: 52 bytes

void FUN_80240218(int param_1,undefined param_2,char param_3)

{
  if (param_1 == 0) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) == '\x02') && (param_3 == '\0')) {
    return;
  }
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0xc) = param_2;
  return;
}

