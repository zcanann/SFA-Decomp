// Function: FUN_8004c264
// Entry: 8004c264
// Size: 128 bytes

void FUN_8004c264(int param_1,undefined4 param_2)

{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025a8f0(param_1 + 0x20,param_2,param_2);
    }
    else {
      FUN_8025a748(param_1 + 0x20,*(undefined4 *)(param_1 + 0x40));
    }
    if (*(int *)(param_1 + 0x50) != 0) {
      FUN_80053c40(param_1,&DAT_803779a0);
      FUN_8025a8f0(&DAT_803779a0,1);
    }
  }
  return;
}

