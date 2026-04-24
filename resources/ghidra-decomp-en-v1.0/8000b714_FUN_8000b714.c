// Function: FUN_8000b714
// Entry: 8000b714
// Size: 168 bytes

void FUN_8000b714(int param_1)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  piVar2 = &DAT_80336000;
  iVar4 = 0x37;
  do {
    iVar3 = *piVar2;
    if (iVar3 != -1) {
      if (param_1 == 0) {
        if (*(char *)((int)piVar2 + 6) != '\0') {
          FUN_802727a8(iVar3,7,*(undefined *)((int)piVar2 + 7));
        }
      }
      else {
        FUN_802727a8(iVar3,7,0);
      }
      *(char *)((int)piVar2 + 6) = (char)param_1;
    }
    piVar2 = piVar2 + 0xe;
    bVar1 = iVar4 != 0;
    iVar4 = iVar4 + -1;
  } while (bVar1);
  return;
}

