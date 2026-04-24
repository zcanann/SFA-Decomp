// Function: FUN_80060cbc
// Entry: 80060cbc
// Size: 80 bytes

void FUN_80060cbc(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = 0;
  uVar2 = (uint)DAT_803ddb18;
  if (uVar2 == 0) {
    return;
  }
  if ((8 < uVar2) && (uVar4 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
    do {
      iVar3 = iVar3 + 8;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
  iVar1 = uVar2 - iVar3;
  if ((int)uVar2 <= iVar3) {
    return;
  }
  do {
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}

