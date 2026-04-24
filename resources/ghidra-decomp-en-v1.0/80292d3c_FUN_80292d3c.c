// Function: FUN_80292d3c
// Entry: 80292d3c
// Size: 132 bytes

void FUN_80292d3c(void)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  double extraout_f1;
  double dVar4;
  
  puVar2 = (uint *)FUN_80286050();
  dVar4 = ABS((double)(float)extraout_f1);
  iVar3 = FUN_80285fb4(DOUBLE_803e7c00 * dVar4);
  uVar1 = iVar3 + 1U & 0xfffffffe;
  *puVar2 = uVar1;
  FUN_8028609c(-(DOUBLE_803e7c08 * ((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e7c10) - dVar4));
  return;
}

