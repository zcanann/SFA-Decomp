// Function: FUN_802734d8
// Entry: 802734d8
// Size: 240 bytes

void FUN_802734d8(uint param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = 0;
  for (uVar3 = 0; uVar3 < DAT_803bdfc0; uVar3 = uVar3 + 1) {
    iVar2 = DAT_803deee8 + iVar4;
    if ((param_1 & 0xff) == (uint)*(byte *)(iVar2 + 0x11f)) {
      if (*(int *)(iVar2 + 0xf4) == -1) {
        bVar1 = FUN_802839b8(uVar3);
        if (bVar1) {
          FUN_80284270(uVar3);
        }
      }
      else {
        FUN_8027a830(*(uint *)(*(int *)(iVar2 + 0xf8) + 8));
      }
    }
    iVar4 = iVar4 + 0x404;
  }
  FUN_80285258();
  (&DAT_803be624)[param_1 & 0xff] = 0;
  (&DAT_803be664)[param_1 & 0xff] = 0;
  (&DAT_803deed4)[param_1 & 0xff] = 0xff;
  (&DAT_803deec4)[param_1 & 0xff] = 0xff;
  FUN_80285220();
  FUN_802842e4(param_1);
  return;
}

