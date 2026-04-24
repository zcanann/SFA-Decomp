// Function: FUN_8025ae2c
// Entry: 8025ae2c
// Size: 380 bytes

void FUN_8025ae2c(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  uint unaff_r28;
  uint unaff_r29;
  uint uVar6;
  
  if (*(int *)(DAT_803dc5a8 + 0x4dc) != 0xff) {
    uVar3 = *(uint *)(DAT_803dc5a8 + 0x204);
    for (uVar6 = 0; uVar6 < (uVar3 >> 0x10 & 7); uVar6 = uVar6 + 1) {
      if (uVar6 == 2) {
        unaff_r29 = *(uint *)(DAT_803dc5a8 + 0x120) >> 0xc & 7;
        unaff_r28 = *(uint *)(DAT_803dc5a8 + 0x120) >> 0xf & 7;
      }
      else if ((int)uVar6 < 2) {
        if (uVar6 == 0) {
          unaff_r29 = *(uint *)(DAT_803dc5a8 + 0x120) & 7;
          unaff_r28 = *(uint *)(DAT_803dc5a8 + 0x120) >> 3 & 7;
        }
        else if (-1 < (int)uVar6) {
          unaff_r29 = *(uint *)(DAT_803dc5a8 + 0x120) >> 6 & 7;
          unaff_r28 = *(uint *)(DAT_803dc5a8 + 0x120) >> 9 & 7;
        }
      }
      else if ((int)uVar6 < 4) {
        unaff_r29 = *(uint *)(DAT_803dc5a8 + 0x120) >> 0x12 & 7;
        unaff_r28 = *(uint *)(DAT_803dc5a8 + 0x120) >> 0x15 & 7;
      }
      if ((*(uint *)(DAT_803dc5a8 + 0x4dc) & 1 << unaff_r28) == 0) {
        FUN_8025ad60(unaff_r29,unaff_r28);
      }
    }
    iVar5 = 0;
    for (uVar6 = 0; uVar6 < (uVar3 >> 10 & 0xf) + 1; uVar6 = uVar6 + 1) {
      puVar4 = (uint *)(DAT_803dc5a8 + (uVar6 & 0x7ffffffe) * 2 + 0x100);
      uVar2 = *(uint *)(DAT_803dc5a8 + iVar5 + 0x49c) & 0xfffffeff;
      if ((uVar6 & 1) == 0) {
        uVar1 = *puVar4 >> 3;
      }
      else {
        uVar1 = *puVar4 >> 0xf;
      }
      if (((uVar2 != 0xff) && ((*(uint *)(DAT_803dc5a8 + 0x4dc) & 1 << (uVar1 & 7)) == 0)) &&
         ((*(uint *)(DAT_803dc5a8 + 0x4e0) & 1 << uVar6) != 0)) {
        FUN_8025ad60(uVar2,uVar1 & 7);
      }
      iVar5 = iVar5 + 4;
    }
  }
  return;
}

