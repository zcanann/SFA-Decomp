// Function: FUN_8018c028
// Entry: 8018c028
// Size: 132 bytes

void FUN_8018c028(int param_1)

{
  if (*(char *)(param_1 + 0x37) == -1) {
    FUN_8025c584(0,1,0,5);
  }
  else {
    FUN_8025c584(1,4,1,5);
  }
  FUN_80070310(1,3,0);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  return;
}

