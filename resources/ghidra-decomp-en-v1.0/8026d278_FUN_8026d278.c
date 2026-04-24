// Function: FUN_8026d278
// Entry: 8026d278
// Size: 464 bytes

void FUN_8026d278(uint param_1)

{
  byte bVar1;
  uint uVar2;
  int **ppiVar3;
  int **ppiVar4;
  int iVar5;
  undefined4 *puVar6;
  int **ppiVar7;
  uint uVar8;
  
  for (ppiVar3 = (int **)DAT_803de234; ppiVar4 = DAT_803de230, ppiVar3 != (int **)0x0;
      ppiVar3 = (int **)*ppiVar3) {
    if (ppiVar3[3] == (int *)(param_1 & 0x7fffffff)) {
      uVar2 = param_1 & 0x80000000 | (uint)*(byte *)((int)ppiVar3 + 9);
      goto LAB_8026d2f0;
    }
  }
  do {
    if (ppiVar4 == (int **)0x0) {
      uVar2 = 0xffffffff;
LAB_8026d2f0:
      if (uVar2 != 0xffffffff) {
        if ((uVar2 & 0x80000000) == 0) {
          iVar5 = uVar2 * 0x1868;
          bVar1 = (&DAT_803b0958)[iVar5];
          ppiVar3 = (int **)(&DAT_803b0950 + uVar2 * 0x61a);
          if (bVar1 == 2) {
            if ((int **)(&DAT_803b0954)[uVar2 * 0x61a] == (int **)0x0) {
              DAT_803de230 = (int **)*ppiVar3;
            }
            else {
              *(int **)(&DAT_803b0954)[uVar2 * 0x61a] = *ppiVar3;
            }
          }
          else if ((bVar1 < 2) && (bVar1 != 0)) {
            if ((int **)(&DAT_803b0954)[uVar2 * 0x61a] == (int **)0x0) {
              DAT_803de234 = *ppiVar3;
            }
            else {
              *(int **)(&DAT_803b0954)[uVar2 * 0x61a] = *ppiVar3;
            }
            uVar8 = 0;
            ppiVar4 = ppiVar3;
            do {
              for (ppiVar7 = (int **)ppiVar4[0x399]; ppiVar7 != (int **)0x0;
                  ppiVar7 = (int **)*ppiVar7) {
                FUN_8027a0cc(ppiVar7[2]);
              }
              uVar8 = uVar8 + 1;
              ppiVar4 = ppiVar4 + 1;
            } while (uVar8 < 2);
            for (puVar6 = *(undefined4 **)(iVar5 + -0x7fc4e844); puVar6 != (undefined4 *)0x0;
                puVar6 = (undefined4 *)*puVar6) {
              FUN_8027a0cc(puVar6[2]);
            }
            FUN_8026bf54(ppiVar3);
          }
          if (*ppiVar3 != (int *)0x0) {
            (*ppiVar3)[1] = (&DAT_803b0954)[uVar2 * 0x61a];
          }
          (&DAT_803b0958)[iVar5] = 0;
          if (DAT_803de22c != (int **)0x0) {
            DAT_803de22c[1] = (int *)ppiVar3;
          }
          *ppiVar3 = (int *)DAT_803de22c;
          (&DAT_803b0954)[uVar2 * 0x61a] = 0;
          DAT_803de22c = ppiVar3;
        }
        else {
          iVar5 = (uVar2 & 0x7fffffff) * 0x1868;
          if ((&DAT_803b0958)[iVar5] != '\0') {
            *(undefined4 *)(iVar5 + -0x7fc4e7d4) = 0;
          }
        }
      }
      return;
    }
    if (ppiVar4[3] == (int *)(param_1 & 0x7fffffff)) {
      uVar2 = param_1 & 0x80000000 | (uint)*(byte *)((int)ppiVar4 + 9);
      goto LAB_8026d2f0;
    }
    ppiVar4 = (int **)*ppiVar4;
  } while( true );
}

