// Function: FUN_80264f28
// Entry: 80264f28
// Size: 240 bytes

void FUN_80264f28(void)

{
  byte bVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  
  iVar3 = 0;
  iVar5 = 1;
  do {
    uVar2 = (undefined)iVar5;
    bVar1 = *(byte *)(DAT_803de1a4 + iVar5 + -1);
    uVar6 = (uint)bVar1;
    if (uVar6 != 0) {
      uVar7 = (uint)(bVar1 >> 3);
      iVar4 = iVar3;
      if (bVar1 >> 3 != 0) {
        do {
          *(undefined *)(DAT_803de1a8 + iVar3) = uVar2;
          *(undefined *)(DAT_803de1a8 + iVar3 + 1) = uVar2;
          *(undefined *)(DAT_803de1a8 + iVar3 + 2) = uVar2;
          *(undefined *)(DAT_803de1a8 + iVar3 + 3) = uVar2;
          *(undefined *)(DAT_803de1a8 + iVar3 + 4) = uVar2;
          *(undefined *)(DAT_803de1a8 + iVar3 + 5) = uVar2;
          iVar4 = iVar3 + 7;
          *(undefined *)(DAT_803de1a8 + iVar3 + 6) = uVar2;
          iVar3 = iVar3 + 8;
          *(undefined *)(DAT_803de1a8 + iVar4) = uVar2;
          uVar7 = uVar7 - 1;
        } while (uVar7 != 0);
        uVar6 = uVar6 & 7;
        iVar4 = iVar3;
        if ((bVar1 & 7) == 0) goto LAB_80264ffc;
      }
      do {
        iVar3 = iVar4 + 1;
        *(undefined *)(DAT_803de1a8 + iVar4) = uVar2;
        uVar6 = uVar6 - 1;
        iVar4 = iVar3;
      } while (uVar6 != 0);
    }
LAB_80264ffc:
    iVar5 = iVar5 + 1;
    if (0x10 < iVar5) {
      *(undefined *)(DAT_803de1a8 + iVar3) = 0;
      return;
    }
  } while( true );
}

