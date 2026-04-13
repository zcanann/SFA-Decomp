// Function: FUN_80279608
// Entry: 80279608
// Size: 104 bytes

void FUN_80279608(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  DAT_803def64 = 0;
  iVar3 = 0;
  DAT_803def54 = 0;
  DAT_803def58 = 0;
  DAT_803def60 = 0;
  for (uVar4 = 0; uVar4 < DAT_803bdfc0; uVar4 = uVar4 + 1) {
    iVar2 = iVar3 + 0x4c;
    *(undefined4 *)(DAT_803deee8 + iVar3 + 0x34) = 0;
    iVar1 = iVar3 + 0xaa;
    iVar3 = iVar3 + 0x404;
    *(undefined4 *)(DAT_803deee8 + iVar2) = 2;
    *(undefined2 *)(DAT_803deee8 + iVar1) = 0;
  }
  return;
}

