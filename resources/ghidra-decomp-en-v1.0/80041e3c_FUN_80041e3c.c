// Function: FUN_80041e3c
// Entry: 80041e3c
// Size: 1028 bytes

void FUN_80041e3c(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  short *psVar8;
  int *piVar9;
  undefined *puVar10;
  uint *puVar11;
  int iVar12;
  
  iVar2 = FUN_802860c4();
  bVar1 = false;
  iVar12 = 0;
  FUN_80023cbc(2);
  FUN_8024377c();
  iVar6 = DAT_803dcc80;
  FUN_802437a4();
  if (iVar6 == 0) {
    if ((iVar2 == 0) && (DAT_803dcc78 == 0)) {
      FUN_80053700(0);
      DAT_803dcc78 = 6;
    }
    else {
      if (iVar2 != 0) {
        FUN_80022d20(1);
        iVar6 = 0;
        piVar7 = &DAT_8035f3e8;
        psVar8 = &DAT_8035f548;
        piVar9 = &DAT_8035f0a8;
        puVar10 = &DAT_8035eef0;
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
            if (((((*piVar7 != 0) && (*psVar8 != -1)) && (iVar3 = FUN_800232b8(), iVar3 == 0)) &&
                ((iVar2 != 2 ||
                 (((iVar6 != 0x20 && (iVar6 != 0x4b)) && ((iVar6 != 0x23 && (iVar6 != 0x4d))))))))
               && (iVar3 = FUN_80023cc8(*piVar9 + 0x20,0x7d7d7d7d,0), iVar3 != 0)) {
              FUN_80003494(iVar3,*piVar7,*piVar9);
              uVar5 = FUN_80023834(0);
              FUN_80023800(*piVar7);
              *piVar7 = 0;
              *piVar7 = iVar3;
              FUN_80023834(uVar5);
            }
          }
          *puVar10 = 0;
          piVar7 = piVar7 + 1;
          psVar8 = psVar8 + 1;
          piVar9 = piVar9 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
        FUN_80022d20(0xffffffff);
      }
      for (; (!bVar1 && (iVar12 < 10)); iVar12 = iVar12 + 1) {
        bVar1 = true;
        iVar6 = 0;
        puVar11 = &DAT_8035f3e8;
        psVar8 = &DAT_8035f548;
        piVar7 = &DAT_8035f0a8;
        puVar10 = &DAT_8035eef0;
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
            if (((*puVar11 == 0) || (*psVar8 == -1)) || (iVar3 = FUN_800232b8(), iVar3 != 0)) {
              if (((((iVar2 != 2) && (iVar12 != 0)) && ((*puVar11 != 0 && (*psVar8 != -1)))) &&
                  ((iVar3 = FUN_800232b8(), iVar3 == 1 ||
                   (iVar3 = FUN_800232b8(*puVar11), iVar3 == 2)))) &&
                 ((iVar3 = FUN_80023c28(*puVar11), 0x2fff < iVar3 &&
                  (uVar4 = FUN_80023cc8(*piVar7 + 0x20,0x7d7d7d7d,0), uVar4 != 0)))) {
                iVar3 = FUN_800232b8();
                if (iVar3 == 0) {
                  FUN_80003494(uVar4,*puVar11,*piVar7);
                  uVar5 = FUN_80023834(0);
                  FUN_80023800(*puVar11);
                  *puVar11 = 0;
                  *puVar11 = uVar4;
                  FUN_80023834(uVar5);
                  bVar1 = false;
                }
                else {
                  uVar5 = FUN_80023834(0);
                  FUN_80023800(uVar4);
                  FUN_80023834(uVar5);
                }
              }
            }
            else {
              uVar4 = FUN_80023cc8(*piVar7 + 0x20,0x7d7d7d7d,0);
              if (uVar4 != 0) {
                if ((*piVar7 < 210000) || (uVar4 <= *puVar11)) {
                  if ((*piVar7 < 210000) && (uVar4 < *puVar11)) {
                    uVar5 = FUN_80023834(0);
                    FUN_80023800(uVar4);
                    FUN_80023834(uVar5);
                  }
                  else {
                    FUN_80003494(uVar4,*puVar11);
                    uVar5 = FUN_80023834(0);
                    FUN_80023800(*puVar11);
                    *puVar11 = 0;
                    *puVar11 = uVar4;
                    FUN_80023834(uVar5);
                    bVar1 = false;
                  }
                }
                else {
                  uVar5 = FUN_80023834(0);
                  FUN_80023800(uVar4);
                  FUN_80023834(uVar5);
                }
              }
            }
          }
          *puVar10 = 0;
          puVar11 = puVar11 + 1;
          psVar8 = psVar8 + 1;
          piVar7 = piVar7 + 1;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 0x58);
      }
      FUN_80023cbc(0);
    }
  }
  FUN_80286110();
  return;
}

