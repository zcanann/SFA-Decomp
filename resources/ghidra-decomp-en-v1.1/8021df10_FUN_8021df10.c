// Function: FUN_8021df10
// Entry: 8021df10
// Size: 168 bytes

undefined4 FUN_8021df10(int param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)(iVar3 + 0xc49) = *(byte *)(iVar3 + 0xc49) & 0xbf;
    *(undefined *)(iVar3 + 0xc4b) = 10;
  }
  cVar1 = *(char *)(iVar3 + 0xc4b);
  if (cVar1 == '\n') {
    uVar2 = FUN_80020078(0x630);
    if (uVar2 != 0) {
      return 7;
    }
  }
  else if (((cVar1 < '\n') && (cVar1 == '\x01')) && (uVar2 = FUN_80020078(0x62c), uVar2 != 0)) {
    *(undefined *)(iVar3 + 0xc4b) = 2;
  }
  return 0;
}

