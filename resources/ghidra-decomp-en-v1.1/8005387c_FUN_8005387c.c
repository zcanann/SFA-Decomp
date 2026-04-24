// Function: FUN_8005387c
// Entry: 8005387c
// Size: 1344 bytes

void FUN_8005387c(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  
  iVar2 = FUN_80286830();
  iVar10 = 0;
  FUN_80023d80(2);
  FUN_8007d858();
  FUN_80022e1c();
  FUN_8007d858();
  FUN_80022de4(1);
  iVar11 = 0;
  for (iVar8 = 0; bVar1 = false, iVar8 < DAT_803dda3c; iVar8 = iVar8 + 1) {
    iVar3 = DAT_803dda44 + iVar11;
    piVar9 = *(int **)(iVar3 + 4);
    if (((((piVar9 != (int *)0x0) && (*(char *)(iVar3 + 8) != '\0')) &&
         (*(char *)((int)piVar9 + 0x49) == '\0')) &&
        ((*(int *)(iVar3 + 0xc) != -1 && (iVar3 = FUN_8002337c((uint)piVar9), iVar3 == 0)))) &&
       (*piVar9 == 0)) {
      iVar3 = *(int *)(DAT_803dda44 + iVar11 + 0xc);
      uVar7 = FUN_80023d8c(iVar3,-0x5f5f5f60);
      if (uVar7 != 0) {
        if (uVar7 != 0) {
          FUN_80023cec((uint)piVar9);
          FUN_8007d858();
          FUN_80003494(uVar7,(uint)piVar9,iVar3);
          FUN_80242114(uVar7,iVar3);
          FUN_80053ed4(uVar7);
          uVar6 = FUN_800238f8(0);
          FUN_800238c4(*(uint *)(DAT_803dda44 + iVar11 + 4));
          FUN_800238f8(uVar6);
          *(uint *)(DAT_803dda44 + iVar11 + 4) = uVar7;
        }
      }
      else {
        FUN_80023cec((uint)piVar9);
        FUN_8007d858();
      }
    }
    iVar11 = iVar11 + 0x10;
  }
  FUN_80022de4(0xffffffff);
  FUN_8007d858();
  FUN_80022e1c();
  FUN_80041f34();
  for (; (!bVar1 && (iVar10 < 4)); iVar10 = iVar10 + 1) {
    bVar1 = true;
    iVar11 = 0;
    for (iVar8 = 0; iVar8 < DAT_803dda3c; iVar8 = iVar8 + 1) {
      iVar3 = DAT_803dda44 + iVar11;
      piVar9 = *(int **)(iVar3 + 4);
      if ((((piVar9 != (int *)0x0) && (*(char *)(iVar3 + 8) != '\0')) &&
          (*(char *)((int)piVar9 + 0x49) == '\0')) && (*(int *)(iVar3 + 0xc) != -1)) {
        iVar3 = FUN_8002337c((uint)piVar9);
        if ((iVar3 == 0) && (*piVar9 == 0)) {
          iVar3 = *(int *)(DAT_803dda44 + iVar11 + 0xc);
          piVar4 = (int *)FUN_80023d8c(iVar3,-0x5f5f5f60);
          if (piVar4 == (int *)0x0) {
            FUN_80023cec((uint)piVar9);
            FUN_8007d858();
          }
          else {
            iVar5 = FUN_8002337c((uint)piVar4);
            if (iVar5 == 0) {
              if (piVar4 < piVar9) {
                FUN_80023cec((uint)piVar9);
                FUN_8007d858();
                uVar6 = FUN_800238f8(0);
                FUN_800238c4((uint)piVar4);
                FUN_800238f8(uVar6);
              }
              else if (piVar4 != (int *)0x0) {
                FUN_80023cec((uint)piVar9);
                FUN_8007d858();
                bVar1 = false;
                FUN_80003494((uint)piVar4,(uint)piVar9,iVar3);
                FUN_80242114((uint)piVar4,iVar3);
                FUN_80053ed4((int)piVar4);
                uVar6 = FUN_800238f8(0);
                FUN_800238c4(*(uint *)(DAT_803dda44 + iVar11 + 4));
                FUN_800238f8(uVar6);
                *(int **)(DAT_803dda44 + iVar11 + 4) = piVar4;
              }
            }
            else {
              FUN_80023cec((uint)piVar9);
              FUN_8007d858();
              uVar6 = FUN_800238f8(0);
              FUN_800238c4((uint)piVar4);
              FUN_800238f8(uVar6);
            }
          }
        }
        else if (((iVar2 == 0) &&
                 ((iVar3 = FUN_8002337c((uint)piVar9), iVar3 == 1 ||
                  (iVar3 = FUN_8002337c((uint)piVar9), iVar3 == 2)))) &&
                ((*piVar9 == 0 && (uVar7 = FUN_80023cec((uint)piVar9), 0x2fff < (int)uVar7)))) {
          iVar3 = *(int *)(DAT_803dda44 + iVar11 + 0xc);
          uVar7 = FUN_80023d8c(iVar3,-0x5f5f5f60);
          if (uVar7 == 0) {
            FUN_80023cec((uint)piVar9);
            FUN_8007d858();
          }
          else {
            iVar5 = FUN_8002337c(uVar7);
            if (iVar5 == 0) {
              if (uVar7 != 0) {
                FUN_80023cec((uint)piVar9);
                FUN_8007d858();
                bVar1 = false;
                FUN_80003494(uVar7,(uint)piVar9,iVar3);
                FUN_80242114(uVar7,iVar3);
                FUN_80053ed4(uVar7);
                uVar6 = FUN_800238f8(0);
                FUN_800238c4(*(uint *)(DAT_803dda44 + iVar11 + 4));
                FUN_800238f8(uVar6);
                *(uint *)(DAT_803dda44 + iVar11 + 4) = uVar7;
              }
            }
            else {
              FUN_80023cec((uint)piVar9);
              FUN_8007d858();
              uVar6 = FUN_800238f8(0);
              FUN_800238c4(uVar7);
              FUN_800238f8(uVar6);
            }
          }
        }
      }
      iVar11 = iVar11 + 0x10;
    }
    FUN_80022e1c();
  }
  FUN_8007d858();
  FUN_80023d80(0);
  FUN_8028687c();
  return;
}

