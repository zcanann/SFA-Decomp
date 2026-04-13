// Function: FUN_80188138
// Entry: 80188138
// Size: 140 bytes

void FUN_80188138(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if ((*(char *)(*(int *)(iVar1 + 0xb8) + 10) == '\0') &&
     (iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)in_r8), iVar2 != 0)) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

