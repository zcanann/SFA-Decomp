// Function: FUN_802bc36c
// Entry: 802bc36c
// Size: 132 bytes

undefined4 FUN_802bc36c(int param_1)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if (cVar1 == '\x01') {
    iVar2 = FUN_8001ffb4(0x2c3);
    if (iVar2 == 0) {
      uVar3 = 3;
    }
    else {
      uVar3 = 3;
    }
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    iVar2 = FUN_8001ffb4(0x224);
    if (iVar2 == 0) {
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

