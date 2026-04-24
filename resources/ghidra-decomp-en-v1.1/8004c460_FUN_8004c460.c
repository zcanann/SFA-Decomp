// Function: FUN_8004c460
// Entry: 8004c460
// Size: 76 bytes

void FUN_8004c460(int param_1,int param_2)

{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
  }
  return;
}

