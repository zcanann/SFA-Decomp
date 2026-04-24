// Function: FUN_8022de8c
// Entry: 8022de8c
// Size: 320 bytes

void FUN_8022de8c(void)

{
  int iVar1;
  short unaff_r29;
  short unaff_r30;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  iVar1 = FUN_80286834();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (*(char *)(iVar2 + 0x338) != '\0') {
    dVar5 = (double)FUN_802945e0();
    dVar3 = (double)FLOAT_803e7c8c;
    dVar6 = (double)FUN_802945e0();
    dVar4 = (double)FLOAT_803e7bf4;
    unaff_r30 = (short)(int)(dVar3 * dVar5);
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) + unaff_r30;
    unaff_r29 = (short)(int)(dVar4 * dVar6);
    *(short *)(iVar1 + 4) = *(short *)(iVar1 + 4) + unaff_r29;
  }
  FUN_8003b9ec(iVar1);
  if (*(char *)(iVar2 + 0x338) != '\0') {
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) - unaff_r30;
    *(short *)(iVar1 + 4) = *(short *)(iVar1 + 4) - unaff_r29;
  }
  FUN_80286880();
  return;
}

