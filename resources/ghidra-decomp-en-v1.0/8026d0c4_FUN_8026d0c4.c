// Function: FUN_8026d0c4
// Entry: 8026d0c4
// Size: 436 bytes

void FUN_8026d0c4(uint param_1)

{
  bool bVar1;
  int **ppiVar2;
  uint uVar3;
  int iVar4;
  int **ppiVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  for (puVar6 = DAT_803de234; ppiVar2 = DAT_803de230, puVar6 != (undefined4 *)0x0;
      puVar6 = (undefined4 *)*puVar6) {
    if ((int *)puVar6[3] == (int *)(param_1 & 0x7fffffff)) {
      uVar3 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar6 + 9);
      goto LAB_8026d140;
    }
  }
  do {
    if (ppiVar2 == (int **)0x0) {
      uVar3 = 0xffffffff;
LAB_8026d140:
      if (uVar3 != 0xffffffff) {
        if ((uVar3 & 0x80000000) == 0) {
          iVar4 = uVar3 * 0x1868;
          ppiVar2 = (int **)(&DAT_803b0950 + uVar3 * 0x61a);
          if ((&DAT_803b0958)[iVar4] == '\x01') {
            if ((int *)(&DAT_803b0954)[uVar3 * 0x61a] == (int *)0x0) {
              DAT_803de234 = *ppiVar2;
            }
            else {
              *(int *)(&DAT_803b0954)[uVar3 * 0x61a] = (int)*ppiVar2;
            }
            if (*ppiVar2 != (int *)0x0) {
              *(undefined4 *)((int)*ppiVar2 + 4) = (&DAT_803b0954)[uVar3 * 0x61a];
            }
            bVar1 = DAT_803de230 != (int **)0x0;
            *ppiVar2 = (int *)DAT_803de230;
            if (bVar1) {
              ((int *)DAT_803de230)[1] = (int)ppiVar2;
            }
            uVar7 = 0;
            (&DAT_803b0954)[uVar3 * 0x61a] = 0;
            DAT_803de230 = ppiVar2;
            (&DAT_803b0958)[iVar4] = 2;
            ppiVar5 = ppiVar2;
            do {
              for (puVar6 = (undefined4 *)((int *)ppiVar5)[0x399]; puVar6 != (undefined4 *)0x0;
                  puVar6 = (undefined4 *)*puVar6) {
                FUN_8027a0cc(puVar6[2]);
              }
              uVar7 = uVar7 + 1;
              ppiVar5 = (int **)((int *)ppiVar5 + 1);
            } while (uVar7 < 2);
            for (puVar6 = *(undefined4 **)(iVar4 + -0x7fc4e844); puVar6 != (undefined4 *)0x0;
                puVar6 = (undefined4 *)*puVar6) {
              FUN_8027a0cc(puVar6[2]);
            }
            FUN_8026bf54(ppiVar2);
          }
        }
        else {
          iVar4 = (uVar3 & 0x7fffffff) * 0x1868;
          if ((&DAT_803b0958)[iVar4] != '\0') {
            (&DAT_803b182a)[iVar4] = (&DAT_803b182a)[iVar4] | 8;
          }
        }
      }
      return;
    }
    if (ppiVar2[3] == (int *)(param_1 & 0x7fffffff)) {
      uVar3 = param_1 & 0x80000000 | (uint)*(byte *)((int)ppiVar2 + 9);
      goto LAB_8026d140;
    }
    ppiVar2 = (int **)*ppiVar2;
  } while( true );
}

