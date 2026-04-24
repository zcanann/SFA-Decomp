// Function: FUN_801af850
// Entry: 801af850
// Size: 96 bytes

void FUN_801af850(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 < 'H') {
    if (cVar1 == 'E') {
      FUN_8000a518(0xda,0);
    }
  }
  else if (cVar1 < 'J') {
    FUN_8000a518(0x36,0);
  }
  return;
}

