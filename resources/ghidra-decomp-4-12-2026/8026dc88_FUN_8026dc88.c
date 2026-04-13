// Function: FUN_8026dc88
// Entry: 8026dc88
// Size: 268 bytes

void FUN_8026dc88(uint param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  int *piVar6;
  
  for (puVar3 = DAT_803deeb4; puVar4 = DAT_803deeb0, puVar3 != (undefined4 *)0x0;
      puVar3 = (undefined4 *)*puVar3) {
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar5 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026dce8;
    }
  }
  do {
    if (puVar4 == (undefined4 *)0x0) {
      uVar5 = 0xffffffff;
LAB_8026dce8:
      if ((uVar5 & 0x80000000) != 0) {
        iVar2 = (uVar5 & 0x7fffffff) * 0x1868;
        (&DAT_803b248a)[iVar2] = (&DAT_803b248a)[iVar2] & 0xf7;
        return;
      }
      piVar6 = &DAT_803b15b0 + uVar5 * 0x61a;
      if ((&DAT_803b15b8)[uVar5 * 0x1868] == '\x02') {
        if ((int *)(&DAT_803b15b4)[uVar5 * 0x61a] == (int *)0x0) {
          DAT_803deeb0 = (undefined4 *)*piVar6;
        }
        else {
          *(int *)(&DAT_803b15b4)[uVar5 * 0x61a] = *piVar6;
        }
        if (*piVar6 != 0) {
          *(undefined4 *)(*piVar6 + 4) = (&DAT_803b15b4)[uVar5 * 0x61a];
        }
        bVar1 = DAT_803deeb4 != (undefined4 *)0x0;
        *piVar6 = (int)DAT_803deeb4;
        if (bVar1) {
          DAT_803deeb4[1] = (int)piVar6;
        }
        (&DAT_803b15b4)[uVar5 * 0x61a] = 0;
        DAT_803deeb4 = piVar6;
        (&DAT_803b15b8)[uVar5 * 0x1868] = 1;
        return;
      }
      return;
    }
    if (puVar4[3] == (param_1 & 0x7fffffff)) {
      uVar5 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar4 + 9);
      goto LAB_8026dce8;
    }
    puVar4 = (undefined4 *)*puVar4;
  } while( true );
}

