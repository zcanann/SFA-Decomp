// Function: FUN_8000b624
// Entry: 8000b624
// Size: 112 bytes

void FUN_8000b624(void)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = &DAT_80336000;
  iVar3 = 0x37;
  do {
    if (*piVar2 != -1) {
      FUN_80272868();
      *piVar2 = -1;
    }
    piVar2 = piVar2 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

