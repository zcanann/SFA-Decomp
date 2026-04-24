// Function: FUN_8024bc84
// Entry: 8024bc84
// Size: 124 bytes

void FUN_8024bc84(uint param_1)

{
  char cVar2;
  int iVar1;
  char cVar3;
  
  if (param_1 == 0x1234567) {
    cVar2 = -1;
  }
  else if (param_1 == 0x1234568) {
    cVar2 = -2;
  }
  else {
    cVar3 = (char)(param_1 >> 0x18);
    cVar2 = FUN_8024bb68(param_1 & 0xffffff);
    if (5 < param_1 >> 0x18) {
      cVar3 = '\x06';
    }
    cVar2 = cVar2 + cVar3 * '\x1e';
  }
  iVar1 = FUN_802451e4();
  *(char *)(iVar1 + 0x24) = cVar2;
  FUN_8024556c(1);
  return;
}

