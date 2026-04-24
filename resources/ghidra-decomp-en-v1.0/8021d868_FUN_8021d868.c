// Function: FUN_8021d868
// Entry: 8021d868
// Size: 168 bytes

undefined4 FUN_8021d868(int param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)(iVar3 + 0xc49) = *(byte *)(iVar3 + 0xc49) & 0xbf;
    *(undefined *)(iVar3 + 0xc4b) = 10;
  }
  cVar1 = *(char *)(iVar3 + 0xc4b);
  if (cVar1 == '\n') {
    iVar3 = FUN_8001ffb4(0x630);
    if (iVar3 != 0) {
      return 7;
    }
  }
  else if (((cVar1 < '\n') && (cVar1 == '\x01')) && (iVar2 = FUN_8001ffb4(0x62c), iVar2 != 0)) {
    *(undefined *)(iVar3 + 0xc4b) = 2;
  }
  return 0;
}

