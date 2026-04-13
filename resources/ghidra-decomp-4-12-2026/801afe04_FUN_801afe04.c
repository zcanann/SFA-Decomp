// Function: FUN_801afe04
// Entry: 801afe04
// Size: 96 bytes

void FUN_801afe04(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 < 'H') {
    if (cVar1 == 'E') {
      FUN_8000a538((int *)0xda,0);
    }
  }
  else if (cVar1 < 'J') {
    FUN_8000a538((int *)0x36,0);
  }
  return;
}

