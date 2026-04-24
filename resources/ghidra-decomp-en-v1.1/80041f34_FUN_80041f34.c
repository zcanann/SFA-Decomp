// Function: FUN_80041f34
// Entry: 80041f34
// Size: 1028 bytes

void FUN_80041f34(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  uint *puVar7;
  short *psVar8;
  int *piVar9;
  undefined *puVar10;
  int iVar11;
  
  iVar2 = FUN_80286828();
  bVar1 = false;
  iVar11 = 0;
  FUN_80023d80(2);
  FUN_80243e74();
  iVar6 = DAT_803dd900;
  FUN_80243e9c();
  if (iVar6 == 0) {
    if ((iVar2 == 0) && (DAT_803dd8f8 == 0)) {
      FUN_8005387c();
      DAT_803dd8f8 = 6;
    }
    else {
      if (iVar2 != 0) {
        FUN_80022de4(1);
        iVar6 = 0;
        puVar7 = &DAT_80360048;
        psVar8 = &DAT_803601a8;
        piVar9 = &DAT_8035fd08;
        puVar10 = &DAT_8035fb50;
        do {
          switch(iVar6) {
          case 0xd:
          case 0x1b:
          case 0x23:
          case 0x25:
          case 0x2b:
          case 0x30:
          case 0x46:
          case 0x47:
          case 0x4a:
          case 0x4d:
          case 0x54:
          case 0x55:
            if (((((*puVar7 != 0) && (*psVar8 != -1)) && (iVar3 = FUN_8002337c(*puVar7), iVar3 == 0)
                 ) && ((iVar2 != 2 ||
                       (((iVar6 != 0x20 && (iVar6 != 0x4b)) && ((iVar6 != 0x23 && (iVar6 != 0x4d))))
                       )))) && (uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)) {
              FUN_80003494(uVar4,*puVar7,*piVar9);
              uVar5 = FUN_800238f8(0);
              FUN_800238c4(*puVar7);
              *puVar7 = 0;
              *puVar7 = uVar4;
              FUN_800238f8(uVar5);
            }
          }
          *puVar10 = 0;
          puVar7 = puVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
        FUN_80022de4(0xffffffff);
      }
      for (; (!bVar1 && (iVar11 < 10)); iVar11 = iVar11 + 1) {
        bVar1 = true;
        iVar6 = 0;
        puVar7 = &DAT_80360048;
        psVar8 = &DAT_803601a8;
        piVar9 = &DAT_8035fd08;
        puVar10 = &DAT_8035fb50;
        do {
          switch(iVar6) {
          case 0xd:
          case 0x1b:
          case 0x23:
          case 0x25:
          case 0x2b:
          case 0x30:
          case 0x46:
          case 0x47:
          case 0x4a:
          case 0x4d:
          case 0x54:
          case 0x55:
            if (((*puVar7 == 0) || (*psVar8 == -1)) || (iVar3 = FUN_8002337c(*puVar7), iVar3 != 0))
            {
              if (((((iVar2 != 2) && (iVar11 != 0)) && ((*puVar7 != 0 && (*psVar8 != -1)))) &&
                  ((iVar3 = FUN_8002337c(*puVar7), iVar3 == 1 ||
                   (iVar3 = FUN_8002337c(*puVar7), iVar3 == 2)))) &&
                 ((uVar4 = FUN_80023cec(*puVar7), 0x2fff < (int)uVar4 &&
                  (uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d), uVar4 != 0)))) {
                iVar3 = FUN_8002337c(uVar4);
                if (iVar3 == 0) {
                  FUN_80003494(uVar4,*puVar7,*piVar9);
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(*puVar7);
                  *puVar7 = 0;
                  *puVar7 = uVar4;
                  FUN_800238f8(uVar5);
                  bVar1 = false;
                }
                else {
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(uVar4);
                  FUN_800238f8(uVar5);
                }
              }
            }
            else {
              uVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d);
              if (uVar4 != 0) {
                iVar3 = *piVar9;
                if ((iVar3 < 210000) || (uVar4 <= *puVar7)) {
                  if ((iVar3 < 210000) && (uVar4 < *puVar7)) {
                    uVar5 = FUN_800238f8(0);
                    FUN_800238c4(uVar4);
                    FUN_800238f8(uVar5);
                  }
                  else {
                    FUN_80003494(uVar4,*puVar7,iVar3);
                    uVar5 = FUN_800238f8(0);
                    FUN_800238c4(*puVar7);
                    *puVar7 = 0;
                    *puVar7 = uVar4;
                    FUN_800238f8(uVar5);
                    bVar1 = false;
                  }
                }
                else {
                  uVar5 = FUN_800238f8(0);
                  FUN_800238c4(uVar4);
                  FUN_800238f8(uVar5);
                }
              }
            }
          }
          *puVar10 = 0;
          puVar7 = puVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
      }
      FUN_80023d80(0);
    }
  }
  FUN_80286874();
  return;
}

