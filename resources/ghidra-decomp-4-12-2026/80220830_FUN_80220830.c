// Function: FUN_80220830
// Entry: 80220830
// Size: 168 bytes

void FUN_80220830(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  int iVar3;
  
  iVar1 = FUN_80286838();
  iVar3 = *(int *)(iVar1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 0x2c);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_80060630(iVar2);
  }
  if ((in_r8 != '\0') && ((*(byte *)(iVar3 + 0x41) >> 1 & 1) != 0)) {
    FUN_8003b9ec(iVar1);
  }
  FUN_80286884();
  return;
}

