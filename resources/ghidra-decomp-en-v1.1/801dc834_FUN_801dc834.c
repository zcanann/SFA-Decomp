// Function: FUN_801dc834
// Entry: 801dc834
// Size: 200 bytes

void FUN_801dc834(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  int iVar3;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0x4c);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b700((ushort)*(byte *)(iVar2 + 0x20),(ushort)*(byte *)(iVar2 + 0x21),
                 (ushort)*(byte *)(iVar2 + 0x22));
    FUN_8003b9ec(iVar1);
    if ((*(byte *)(iVar3 + 0x4c) & 0x80) != 0) {
      iVar2 = 0;
      do {
        FUN_80038524(iVar1,iVar2,(float *)(iVar3 + 0xc),(undefined4 *)(iVar3 + 0x10),
                     (float *)(iVar3 + 0x14),0);
        iVar3 = iVar3 + 0xc;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 3);
    }
    *(undefined4 *)(iVar1 + 0xf8) = 1;
  }
  FUN_80286888();
  return;
}

