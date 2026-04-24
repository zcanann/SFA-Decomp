// Function: FUN_8017191c
// Entry: 8017191c
// Size: 168 bytes

void FUN_8017191c(void)

{
  float fVar1;
  int iVar2;
  char in_r8;
  
  iVar2 = FUN_80286840();
  if ((*(char *)((int)*(float **)(iVar2 + 0xb8) + 9) == '\0') && (in_r8 != '\0')) {
    fVar1 = **(float **)(iVar2 + 0xb8);
    if (fVar1 != FLOAT_803e4098) {
      FUN_8003b6d8(200,0,0,(char)(int)fVar1);
    }
    FUN_8003b9ec(iVar2);
  }
  FUN_8028688c();
  return;
}

