// Function: FUN_802bcadc
// Entry: 802bcadc
// Size: 132 bytes

undefined4 FUN_802bcadc(int param_1)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if (cVar1 == '\x01') {
    uVar2 = FUN_80020078(0x2c3);
    if (uVar2 == 0) {
      uVar3 = 3;
    }
    else {
      uVar3 = 3;
    }
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    uVar2 = FUN_80020078(0x224);
    if (uVar2 == 0) {
      uVar3 = 2;
    }
    else {
      uVar3 = 3;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

