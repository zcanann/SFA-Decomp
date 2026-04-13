// Function: FUN_800201ac
// Entry: 800201ac
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x80020278) */

void FUN_800201ac(uint param_1,uint param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int unaff_r30;
  int unaff_r31;
  
  uVar2 = FUN_800e8a34();
  if (uVar2 == 0) {
    if ((param_1 & 0x8000) != 0) {
      param_2 = param_2 & 1 ^ 1;
    }
    iVar3 = (int)(short)((ushort)param_1 & 0xfff);
    if ((((iVar3 != 0x95) && (iVar3 != 0x96)) && (param_1 != 0xffffffff)) && (iVar3 < DAT_803dd758))
    {
      iVar3 = iVar3 * 4;
      bVar1 = *(byte *)(DAT_803dd75c + iVar3 + 2);
      uVar2 = (int)(uint)bVar1 >> 6;
      if (uVar2 == 2) {
        unaff_r31 = DAT_803dd760 + 0x24;
        unaff_r30 = 0x144;
      }
      else if (uVar2 < 2) {
        if (uVar2 == 0) {
          unaff_r31 = DAT_803dd760 + 0xef0;
          unaff_r30 = 0x80;
        }
        else {
          unaff_r31 = DAT_803dd760 + 0x564;
          unaff_r30 = 0x74;
        }
      }
      else if (uVar2 < 4) {
        unaff_r31 = DAT_803dd760 + 0x5d8;
        unaff_r30 = 0xac;
      }
      if ((bVar1 & 0x20) != 0) {
        FUN_800ea564();
      }
      uVar6 = (uint)*(ushort *)(DAT_803dd75c + iVar3);
      uVar2 = 1;
      uVar4 = (*(byte *)(DAT_803dd75c + iVar3 + 2) & 0x1f) + uVar6 + 1;
      iVar3 = uVar4 - uVar6;
      if (uVar6 < uVar4) {
        do {
          iVar5 = (int)uVar6 >> 3;
          if (unaff_r30 <= iVar5) {
            return;
          }
          bVar1 = (byte)(1 << (uVar6 & 7));
          if ((param_2 & uVar2) == 0) {
            *(byte *)(unaff_r31 + iVar5) = *(byte *)(unaff_r31 + iVar5) & ~bVar1;
          }
          else {
            *(byte *)(unaff_r31 + iVar5) = *(byte *)(unaff_r31 + iVar5) | bVar1;
          }
          uVar2 = uVar2 << 1;
          uVar6 = uVar6 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
  }
  else {
    FUN_8007d858();
  }
  return;
}

