// Function: FUN_80203afc
// Entry: 80203afc
// Size: 368 bytes

void FUN_80203afc(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(int *)(iVar3 + 0x18) != 0) {
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0xc) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x10) = *(undefined4 *)(iVar1 + 0x10);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    *(float *)(*(int *)(iVar3 + 0x18) + 0x10) =
         *(float *)(*(int *)(iVar3 + 0x18) + 0x10) + FLOAT_803e6f68;
  }
  if (((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e6f40) {
      FUN_8003b6d8(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b9ec(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8009a010((double)FLOAT_803e6f60,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar3 + 0x18);
    if ((iVar2 != 0) && (*(int *)(iVar2 + 0x50) != 0)) {
      FUN_80038524(iVar1,3,(float *)(iVar2 + 0xc),(undefined4 *)(iVar2 + 0x10),
                   (float *)(iVar2 + 0x14),0);
      FUN_8003b9ec(*(int *)(iVar3 + 0x18));
    }
  }
  FUN_80286884();
  return;
}

