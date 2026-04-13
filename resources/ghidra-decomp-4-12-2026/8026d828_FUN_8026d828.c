// Function: FUN_8026d828
// Entry: 8026d828
// Size: 436 bytes

void FUN_8026d828(uint param_1)

{
  bool bVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  for (puVar6 = DAT_803deeb4; piVar2 = DAT_803deeb0, puVar6 != (undefined4 *)0x0;
      puVar6 = (undefined4 *)*puVar6) {
    if (puVar6[3] == (param_1 & 0x7fffffff)) {
      uVar3 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar6 + 9);
      goto LAB_8026d8a4;
    }
  }
  do {
    if (piVar2 == (int *)0x0) {
      uVar3 = 0xffffffff;
LAB_8026d8a4:
      if (uVar3 != 0xffffffff) {
        if ((uVar3 & 0x80000000) == 0) {
          iVar4 = uVar3 * 0x1868;
          piVar2 = &DAT_803b15b0 + uVar3 * 0x61a;
          if ((&DAT_803b15b8)[iVar4] == '\x01') {
            if ((int *)(&DAT_803b15b4)[uVar3 * 0x61a] == (int *)0x0) {
              DAT_803deeb4 = (undefined4 *)*piVar2;
            }
            else {
              *(int *)(&DAT_803b15b4)[uVar3 * 0x61a] = *piVar2;
            }
            if (*piVar2 != 0) {
              *(undefined4 *)(*piVar2 + 4) = (&DAT_803b15b4)[uVar3 * 0x61a];
            }
            bVar1 = DAT_803deeb0 != (int *)0x0;
            *piVar2 = (int)DAT_803deeb0;
            if (bVar1) {
              DAT_803deeb0[1] = (int)piVar2;
            }
            uVar7 = 0;
            (&DAT_803b15b4)[uVar3 * 0x61a] = 0;
            DAT_803deeb0 = piVar2;
            (&DAT_803b15b8)[iVar4] = 2;
            piVar5 = piVar2;
            do {
              for (puVar6 = (undefined4 *)piVar5[0x399]; puVar6 != (undefined4 *)0x0;
                  puVar6 = (undefined4 *)*puVar6) {
                FUN_8027a830(puVar6[2]);
              }
              uVar7 = uVar7 + 1;
              piVar5 = piVar5 + 1;
            } while (uVar7 < 2);
            for (puVar6 = *(undefined4 **)(iVar4 + -0x7fc4dbe4); puVar6 != (undefined4 *)0x0;
                puVar6 = (undefined4 *)*puVar6) {
              FUN_8027a830(puVar6[2]);
            }
            FUN_8026c6b8((int)piVar2);
          }
        }
        else {
          iVar4 = (uVar3 & 0x7fffffff) * 0x1868;
          if ((&DAT_803b15b8)[iVar4] != '\0') {
            (&DAT_803b248a)[iVar4] = (&DAT_803b248a)[iVar4] | 8;
          }
        }
      }
      return;
    }
    if (piVar2[3] == (param_1 & 0x7fffffff)) {
      uVar3 = param_1 & 0x80000000 | (uint)*(byte *)((int)piVar2 + 9);
      goto LAB_8026d8a4;
    }
    piVar2 = (int *)*piVar2;
  } while( true );
}

