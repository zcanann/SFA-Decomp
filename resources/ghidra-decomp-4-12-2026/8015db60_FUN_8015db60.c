// Function: FUN_8015db60
// Entry: 8015db60
// Size: 192 bytes

void FUN_8015db60(void)

{
  short *psVar1;
  char in_r8;
  int iVar2;
  
  psVar1 = (short *)FUN_8028683c();
  iVar2 = *(int *)(psVar1 + 0x5c);
  if (((in_r8 != '\0') && (*(int *)(psVar1 + 0x7a) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e39ac) {
      FUN_8003b6d8(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b9ec((int)psVar1);
    FUN_8015d314(psVar1,iVar2);
  }
  FUN_80286888();
  return;
}

