// Function: FUN_80133718
// Entry: 80133718
// Size: 256 bytes

void FUN_80133718(void)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  
  FUN_802860dc();
  bVar4 = 2;
  FUN_80129cbc((double)FLOAT_803e227c,(double)FLOAT_803e2278,(double)FLOAT_803e2280);
  bVar3 = DAT_803dd92a >> 3 & 1;
  if ((bVar3 != 0) && (*(char *)(iRam803dbbcc + 0xad) == '\0')) {
    FUN_8000bb18(0,0x3f1);
  }
  *(byte *)(iRam803dbbcc + 0xad) = bVar3;
  if (DAT_803dd934 == 0) {
    bVar4 = 1;
  }
  for (bVar3 = 0; bVar3 < bVar4; bVar3 = bVar3 + 1) {
    iVar1 = (uint)bVar3 * 4;
    FUN_8003b958(0,0,0,0,*(undefined4 *)(&DAT_803dbbc8 + iVar1),1);
    iVar2 = FUN_8002b588(*(undefined4 *)(&DAT_803dbbc8 + iVar1));
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    *(undefined *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0x37) = 0xff;
  }
  FUN_80129c74();
  FUN_80286128();
  return;
}

