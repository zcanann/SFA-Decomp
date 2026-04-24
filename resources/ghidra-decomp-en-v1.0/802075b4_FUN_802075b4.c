// Function: FUN_802075b4
// Entry: 802075b4
// Size: 96 bytes

void FUN_802075b4(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0xe);
  if (cVar1 == '\0') {
    FUN_8020718c();
  }
  else if (cVar1 == '\x01') {
    FUN_80206f30();
  }
  else if (cVar1 == '\x02') {
    FUN_80206c18();
  }
  else if (cVar1 == '\x03') {
    FUN_80206968();
  }
  return;
}

