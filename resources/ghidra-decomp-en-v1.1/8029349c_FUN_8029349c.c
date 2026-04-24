// Function: FUN_8029349c
// Entry: 8029349c
// Size: 132 bytes

void FUN_8029349c(void)

{
  uint *puVar1;
  int iVar2;
  double extraout_f1;
  
  puVar1 = (uint *)FUN_802867b4();
  iVar2 = FUN_80286718(DOUBLE_803e8898 * ABS((double)(float)extraout_f1));
  *puVar1 = iVar2 + 1U & 0xfffffffe;
  FUN_80286800();
  return;
}

