// Function: FUN_80133868
// Entry: 80133868
// Size: 60 bytes

void FUN_80133868(void)

{
  bool bVar1;
  
  bVar1 = false;
  if ((DAT_803de5c4 == '\x02') && (DAT_803dc818 != '\0')) {
    bVar1 = true;
  }
  if (!bVar1) {
    return;
  }
  DAT_803de5a8 = 5;
  return;
}

