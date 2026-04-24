// Function: FUN_80053700
// Entry: 80053700
// Size: 1344 bytes

void FUN_80053700(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  
  iVar2 = FUN_802860cc();
  iVar10 = 0;
  FUN_80023cbc(2);
  FUN_8007d6dc(s__________________Restruct_textur_8030e1bc);
  FUN_80022d58(1);
  FUN_8007d6dc(s__________________REREGION_8030e1ec);
  FUN_80022d20(1);
  iVar11 = 0;
  for (iVar8 = 0; bVar1 = false, iVar8 < DAT_803dcdbc; iVar8 = iVar8 + 1) {
    iVar3 = DAT_803dcdc4 + iVar11;
    piVar9 = *(int **)(iVar3 + 4);
    if (((((piVar9 != (int *)0x0) && (*(char *)(iVar3 + 8) != '\0')) &&
         (*(char *)((int)piVar9 + 0x49) == '\0')) &&
        ((*(int *)(iVar3 + 0xc) != -1 && (iVar3 = FUN_800232b8(piVar9), iVar3 == 0)))) &&
       (*piVar9 == 0)) {
      uVar7 = *(undefined4 *)(DAT_803dcdc4 + iVar11 + 0xc);
      iVar3 = FUN_80023cc8(uVar7,0xa0a0a0a0,0);
      if (iVar3 != 0) {
        if (iVar3 != 0) {
          uVar5 = FUN_80023c28(piVar9);
          FUN_8007d6dc(s_texRestructRefs_Optimal_ReRegion_8030e24c,piVar9,iVar3,uVar5);
          FUN_80003494(iVar3,piVar9,uVar7);
          FUN_80241a1c(iVar3,uVar7);
          FUN_80053d58(iVar3);
          uVar7 = FUN_80023834(0);
          FUN_80023800(*(undefined4 *)(DAT_803dcdc4 + iVar11 + 4));
          FUN_80023834(uVar7);
          *(int *)(DAT_803dcdc4 + iVar11 + 4) = iVar3;
        }
      }
      else {
        uVar7 = FUN_80023c28(piVar9);
        FUN_8007d6dc(s_texRestructRefs_No_Space_to_ReRe_8030e20c,piVar9,uVar7);
      }
    }
    iVar11 = iVar11 + 0x10;
  }
  FUN_80022d20(0xffffffff);
  FUN_8007d6dc(s__________________AFTER_REREGION_8030e290);
  FUN_80022d58(1);
  FUN_80041e3c(2);
  for (; (!bVar1 && (iVar10 < 4)); iVar10 = iVar10 + 1) {
    bVar1 = true;
    iVar11 = 0;
    for (iVar8 = 0; iVar8 < DAT_803dcdbc; iVar8 = iVar8 + 1) {
      iVar3 = DAT_803dcdc4 + iVar11;
      piVar9 = *(int **)(iVar3 + 4);
      if ((((piVar9 != (int *)0x0) && (*(char *)(iVar3 + 8) != '\0')) &&
          (*(char *)((int)piVar9 + 0x49) == '\0')) && (*(int *)(iVar3 + 0xc) != -1)) {
        iVar3 = FUN_800232b8(piVar9);
        if ((iVar3 == 0) && (*piVar9 == 0)) {
          uVar7 = *(undefined4 *)(DAT_803dcdc4 + iVar11 + 0xc);
          piVar4 = (int *)FUN_80023cc8(uVar7,0xa0a0a0a0,0);
          if (piVar4 == (int *)0x0) {
            uVar7 = FUN_80023c28(piVar9);
            FUN_8007d6dc(s_texRestructRefs_No_Space_to_Rest_8030e2b4,piVar9,uVar7);
          }
          else {
            iVar3 = FUN_800232b8();
            if (iVar3 == 0) {
              if (piVar4 < piVar9) {
                uVar7 = FUN_80023c28(piVar9);
                FUN_8007d6dc(s_texRestructRefs_SubOptimal_Restr_8030e330,piVar9,piVar4,uVar7);
                uVar7 = FUN_80023834(0);
                FUN_80023800(piVar4);
                FUN_80023834(uVar7);
              }
              else if (piVar4 != (int *)0x0) {
                uVar5 = FUN_80023c28(piVar9);
                FUN_8007d6dc(s_texRestructRefs_Optimal_Restruct_8030e378,piVar9,piVar4,uVar5);
                bVar1 = false;
                FUN_80003494(piVar4,piVar9,uVar7);
                FUN_80241a1c(piVar4,uVar7);
                FUN_80053d58(piVar4);
                uVar7 = FUN_80023834(0);
                FUN_80023800(*(undefined4 *)(DAT_803dcdc4 + iVar11 + 4));
                FUN_80023834(uVar7);
                *(int **)(DAT_803dcdc4 + iVar11 + 4) = piVar4;
              }
            }
            else {
              uVar7 = FUN_80023c28(piVar9);
              FUN_8007d6dc(s_texRestructRefs_Wrong_region_fro_8030e2f4,piVar9,piVar4,uVar7);
              uVar7 = FUN_80023834(0);
              FUN_80023800(piVar4);
              FUN_80023834(uVar7);
            }
          }
        }
        else if (((iVar2 == 0) &&
                 ((iVar3 = FUN_800232b8(piVar9), iVar3 == 1 ||
                  (iVar3 = FUN_800232b8(piVar9), iVar3 == 2)))) &&
                ((*piVar9 == 0 && (iVar3 = FUN_80023c28(piVar9), 0x2fff < iVar3)))) {
          uVar7 = *(undefined4 *)(DAT_803dcdc4 + iVar11 + 0xc);
          iVar3 = FUN_80023cc8(uVar7,0xa0a0a0a0,0);
          if (iVar3 == 0) {
            uVar7 = FUN_80023c28(piVar9);
            FUN_8007d6dc(s_texRestructRefs_No_Space_to_Rest_8030e2b4,piVar9,uVar7);
          }
          else {
            iVar6 = FUN_800232b8();
            if (iVar6 == 0) {
              if (iVar3 != 0) {
                uVar5 = FUN_80023c28(piVar9);
                FUN_8007d6dc(s_texRestructRefs_ReRegioned_alloc_8030e420,piVar9,iVar3,uVar5);
                bVar1 = false;
                FUN_80003494(iVar3,piVar9,uVar7);
                FUN_80241a1c(iVar3,uVar7);
                FUN_80053d58(iVar3);
                uVar7 = FUN_80023834(0);
                FUN_80023800(*(undefined4 *)(DAT_803dcdc4 + iVar11 + 4));
                FUN_80023834(uVar7);
                *(int *)(DAT_803dcdc4 + iVar11 + 4) = iVar3;
              }
            }
            else {
              uVar7 = FUN_80023c28(piVar9);
              FUN_8007d6dc(s_texRestructRefs_ReRegioned_alloc_8030e3c0,piVar9,iVar3,uVar7);
              uVar7 = FUN_80023834(0);
              FUN_80023800(iVar3);
              FUN_80023834(uVar7);
            }
          }
        }
      }
      iVar11 = iVar11 + 0x10;
    }
    FUN_80022d58(1);
  }
  FUN_8007d6dc(s__________________Restruct_textur_8030e478,iVar10);
  FUN_80023cbc(0);
  FUN_80286118();
  return;
}

