// Function: FUN_8024c3e8
// Entry: 8024c3e8
// Size: 124 bytes

void FUN_8024c3e8(uint param_1)

{
  char cVar2;
  undefined2 *puVar1;
  char cVar3;
  
  if (param_1 == 0x1234567) {
    cVar2 = -1;
  }
  else if (param_1 == 0x1234568) {
    cVar2 = -2;
  }
  else {
    cVar3 = (char)(param_1 >> 0x18);
    cVar2 = FUN_8024c2cc(param_1 & 0xffffff);
    if (5 < param_1 >> 0x18) {
      cVar3 = '\x06';
    }
    cVar2 = cVar2 + cVar3 * '\x1e';
  }
  puVar1 = FUN_802458dc();
  *(char *)(puVar1 + 0x12) = cVar2;
  FUN_80245c64(1);
  return;
}

