// Function: FUN_801e2464
// Entry: 801e2464
// Size: 148 bytes

undefined4 FUN_801e2464(uint param_1)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 0x29) == '\x01') {
    cVar1 = *(char *)(iVar3 + 0x7a);
    if (((cVar1 == '\0') || (cVar1 == '\x01')) || (cVar1 == '\x02')) {
      *(char *)(iVar3 + 0x7c) = *(char *)(iVar3 + 0x7c) + '\x01';
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    if ('\x01' < *(char *)(iVar3 + 0x29)) {
      FUN_8000bb38(param_1,0x3f);
    }
    *(char *)(iVar3 + 0x2b) = *(char *)(iVar3 + 0x2b) + '\x01';
    uVar2 = 1;
  }
  return uVar2;
}

