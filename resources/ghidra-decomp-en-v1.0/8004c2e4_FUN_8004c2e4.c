// Function: FUN_8004c2e4
// Entry: 8004c2e4
// Size: 76 bytes

void FUN_8004c2e4(int param_1,undefined4 param_2)

{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025a8f0(param_1 + 0x20,param_2,param_2);
    }
    else {
      FUN_8025a748(param_1 + 0x20,*(undefined4 *)(param_1 + 0x40));
    }
  }
  return;
}

