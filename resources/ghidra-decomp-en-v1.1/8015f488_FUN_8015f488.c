// Function: FUN_8015f488
// Entry: 8015f488
// Size: 180 bytes

void FUN_8015f488(void)

{
  float fVar1;
  int iVar2;
  char in_r8;
  
  iVar2 = FUN_80286840();
  if (((in_r8 != '\0') && (*(int *)(iVar2 + 0xf4) == 0)) &&
     (*(short *)(*(int *)(iVar2 + 0xb8) + 0x402) != 0)) {
    fVar1 = *(float *)(*(int *)(iVar2 + 0xb8) + 1000);
    if (fVar1 != FLOAT_803e3a60) {
      FUN_8003b6d8(200,0,0,(char)(int)fVar1);
    }
    FUN_8003b9ec(iVar2);
  }
  FUN_8028688c();
  return;
}

