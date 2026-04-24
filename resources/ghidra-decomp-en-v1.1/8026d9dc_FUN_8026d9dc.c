// Function: FUN_8026d9dc
// Entry: 8026d9dc
// Size: 464 bytes

void FUN_8026d9dc(uint param_1)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  undefined4 *puVar7;
  uint uVar8;
  
  for (puVar7 = DAT_803deeb4; puVar3 = DAT_803deeb0, puVar7 != (undefined4 *)0x0;
      puVar7 = (undefined4 *)*puVar7) {
    if (puVar7[3] == (param_1 & 0x7fffffff)) {
      uVar2 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar7 + 9);
      goto LAB_8026da54;
    }
  }
  do {
    if (puVar3 == (undefined4 *)0x0) {
      uVar2 = 0xffffffff;
LAB_8026da54:
      if (uVar2 != 0xffffffff) {
        if ((uVar2 & 0x80000000) == 0) {
          iVar4 = uVar2 * 0x1868;
          bVar1 = (&DAT_803b15b8)[iVar4];
          piVar5 = &DAT_803b15b0 + uVar2 * 0x61a;
          if (bVar1 == 2) {
            if ((int *)(&DAT_803b15b4)[uVar2 * 0x61a] == (int *)0x0) {
              DAT_803deeb0 = (undefined4 *)*piVar5;
            }
            else {
              *(int *)(&DAT_803b15b4)[uVar2 * 0x61a] = *piVar5;
            }
          }
          else if ((bVar1 < 2) && (bVar1 != 0)) {
            if ((int *)(&DAT_803b15b4)[uVar2 * 0x61a] == (int *)0x0) {
              DAT_803deeb4 = (undefined4 *)*piVar5;
            }
            else {
              *(int *)(&DAT_803b15b4)[uVar2 * 0x61a] = *piVar5;
            }
            uVar8 = 0;
            piVar6 = piVar5;
            do {
              for (puVar7 = (undefined4 *)piVar6[0x399]; puVar7 != (undefined4 *)0x0;
                  puVar7 = (undefined4 *)*puVar7) {
                FUN_8027a830(puVar7[2]);
              }
              uVar8 = uVar8 + 1;
              piVar6 = piVar6 + 1;
            } while (uVar8 < 2);
            for (puVar7 = *(undefined4 **)(iVar4 + -0x7fc4dbe4); puVar7 != (undefined4 *)0x0;
                puVar7 = (undefined4 *)*puVar7) {
              FUN_8027a830(puVar7[2]);
            }
            FUN_8026c6b8((int)piVar5);
          }
          if (*piVar5 != 0) {
            *(undefined4 *)(*piVar5 + 4) = (&DAT_803b15b4)[uVar2 * 0x61a];
          }
          (&DAT_803b15b8)[iVar4] = 0;
          if (DAT_803deeac != (int *)0x0) {
            DAT_803deeac[1] = (int)piVar5;
          }
          *piVar5 = (int)DAT_803deeac;
          (&DAT_803b15b4)[uVar2 * 0x61a] = 0;
          DAT_803deeac = piVar5;
        }
        else {
          iVar4 = (uVar2 & 0x7fffffff) * 0x1868;
          if ((&DAT_803b15b8)[iVar4] != '\0') {
            *(undefined4 *)(iVar4 + -0x7fc4db74) = 0;
          }
        }
      }
      return;
    }
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar2 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026da54;
    }
    puVar3 = (undefined4 *)*puVar3;
  } while( true );
}

