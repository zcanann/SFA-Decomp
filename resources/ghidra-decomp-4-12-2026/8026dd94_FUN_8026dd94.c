// Function: FUN_8026dd94
// Entry: 8026dd94
// Size: 180 bytes

void FUN_8026dd94(uint param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  for (puVar2 = DAT_803deeb4; puVar3 = DAT_803deeb0, puVar2 != (undefined4 *)0x0;
      puVar2 = (undefined4 *)*puVar2) {
    if (puVar2[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar2 + 9);
      goto LAB_8026ddfc;
    }
  }
  do {
    if (puVar3 == (undefined4 *)0x0) {
      uVar4 = 0xffffffff;
LAB_8026ddfc:
      if (uVar4 == 0xffffffff) {
        return;
      }
      if ((uVar4 & 0x80000000) != 0) {
        iVar1 = (uVar4 & 0x7fffffff) * 0x1868;
        (&DAT_803b248a)[iVar1] = (&DAT_803b248a)[iVar1] | 0x10;
        *(undefined4 *)(&DAT_803b2480 + iVar1) = param_2;
        *(undefined4 *)(&DAT_803b2484 + iVar1) = param_3;
        return;
      }
      *(undefined4 *)(&DAT_803b16cc + uVar4 * 0x1868) = param_2;
      *(undefined4 *)(&DAT_803b16d0 + uVar4 * 0x1868) = param_3;
      return;
    }
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026ddfc;
    }
    puVar3 = (undefined4 *)*puVar3;
  } while( true );
}

