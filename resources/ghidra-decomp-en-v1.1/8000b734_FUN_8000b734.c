// Function: FUN_8000b734
// Entry: 8000b734
// Size: 168 bytes

void FUN_8000b734(int param_1)

{
  bool bVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  
  puVar2 = &DAT_80336c60;
  iVar4 = 0x37;
  do {
    uVar3 = *puVar2;
    if (uVar3 != 0xffffffff) {
      if (param_1 == 0) {
        if (*(char *)((int)puVar2 + 6) != '\0') {
          FUN_80272f0c(uVar3,7,*(byte *)((int)puVar2 + 7));
        }
      }
      else {
        FUN_80272f0c(uVar3,7,0);
      }
      *(char *)((int)puVar2 + 6) = (char)param_1;
    }
    puVar2 = puVar2 + 0xe;
    bVar1 = iVar4 != 0;
    iVar4 = iVar4 + -1;
  } while (bVar1);
  return;
}

