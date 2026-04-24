// Function: FUN_801690a8
// Entry: 801690a8
// Size: 268 bytes

void FUN_801690a8(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e3cf8) {
      FUN_8003b6d8(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b9ec(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8009a010((double)FLOAT_803e3d10,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar2 + 0x40c);
    FUN_80038524(iVar1,2,(float *)(iVar2 + 0x10),(undefined4 *)(iVar2 + 0x14),
                 (float *)(iVar2 + 0x18),0);
    FUN_80038524(iVar1,1,(float *)(iVar2 + 0x28),(undefined4 *)(iVar2 + 0x2c),
                 (float *)(iVar2 + 0x30),0);
  }
  FUN_80286888();
  return;
}

