// Function: FUN_80133aa0
// Entry: 80133aa0
// Size: 256 bytes

void FUN_80133aa0(void)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  
  FUN_80286840();
  bVar4 = 2;
  FUN_80129ff8((double)FLOAT_803e2f0c,(double)FLOAT_803e2f08,(double)FLOAT_803e2f10);
  bVar3 = DAT_803de5aa >> 3 & 1;
  if ((bVar3 != 0) && (*(char *)(iRam803dc834 + 0xad) == '\0')) {
    FUN_8000bb38(0,0x3f1);
  }
  *(byte *)(iRam803dc834 + 0xad) = bVar3;
  if (DAT_803de5b4 == 0) {
    bVar4 = 1;
  }
  for (bVar3 = 0; bVar3 < bVar4; bVar3 = bVar3 + 1) {
    iVar1 = (uint)bVar3 * 4;
    FUN_8003ba50(0,0,0,0,*(int *)(&DAT_803dc830 + iVar1),1);
    iVar2 = FUN_8002b660(*(int *)(&DAT_803dc830 + iVar1));
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    *(undefined *)(*(int *)(&DAT_803dc830 + iVar1) + 0x37) = 0xff;
  }
  FUN_80129fb0();
  FUN_8028688c();
  return;
}

