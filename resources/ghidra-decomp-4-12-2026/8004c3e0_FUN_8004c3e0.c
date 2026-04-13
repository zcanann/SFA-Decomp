// Function: FUN_8004c3e0
// Entry: 8004c3e0
// Size: 128 bytes

void FUN_8004c3e0(int param_1,int param_2)

{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
    if (*(int *)(param_1 + 0x50) != 0) {
      FUN_80053dbc(param_1,(uint *)&DAT_80378600);
      FUN_8025b054((uint *)&DAT_80378600,1);
    }
  }
  return;
}

