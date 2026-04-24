// Function: FUN_8015355c
// Entry: 8015355c
// Size: 228 bytes

void FUN_8015355c(int param_1,int param_2)

{
  char cVar1;
  
  cVar1 = '\0';
  switch(*(undefined2 *)(param_1 + 0xa0)) {
  case 1:
    cVar1 = '\x01';
    break;
  case 2:
    cVar1 = '\x01';
    break;
  case 3:
    cVar1 = '\x01';
    break;
  case 5:
    if ((*(uint *)(param_2 + 0x2dc) & 0x80000000) != 0) {
      cVar1 = '\n';
    }
  }
  if ((cVar1 != '\0') && ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0)) {
    for (; cVar1 != '\0'; cVar1 = cVar1 + -1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x802,0,2,0xffffffff,0);
    }
  }
  return;
}

