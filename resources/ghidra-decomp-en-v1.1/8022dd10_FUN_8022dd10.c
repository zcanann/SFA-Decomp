// Function: FUN_8022dd10
// Entry: 8022dd10
// Size: 132 bytes

void FUN_8022dd10(int param_1,char param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar2 + 0x468) = *(char *)(iVar2 + 0x468) + param_2;
  cVar1 = *(char *)(iVar2 + 0x468);
  if (cVar1 < '\0') {
    cVar1 = '\0';
  }
  else if (*(char *)(iVar2 + 0x469) < cVar1) {
    cVar1 = *(char *)(iVar2 + 0x469);
  }
  *(char *)(iVar2 + 0x468) = cVar1;
  if ('\x03' < *(char *)(iVar2 + 0x468)) {
    FUN_8000b7dc(param_1,4);
  }
  return;
}

