// Function: FUN_8026dbac
// Entry: 8026dbac
// Size: 220 bytes

void FUN_8026dbac(uint param_1,undefined2 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  for (puVar2 = DAT_803deeb4; puVar3 = DAT_803deeb0, puVar2 != (undefined4 *)0x0;
      puVar2 = (undefined4 *)*puVar2) {
    if (puVar2[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar2 + 9);
      goto LAB_8026dc14;
    }
  }
  do {
    if (puVar3 == (undefined4 *)0x0) {
      uVar4 = 0xffffffff;
LAB_8026dc14:
      if ((uVar4 & 0x80000000) != 0) {
        iVar1 = (uVar4 & 0x7fffffff) * 0x1868;
        (&DAT_803b248a)[iVar1] = (&DAT_803b248a)[iVar1] | 0x20;
        *(undefined2 *)(&DAT_803b2488 + iVar1) = param_2;
        return;
      }
      iVar1 = uVar4 * 0x1868;
      *(undefined2 *)(&DAT_803b2aca + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2b02 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2b3a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2b72 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2baa + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2be2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2c1a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2c52 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2c8a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2cc2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2cfa + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2d32 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2d6a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2da2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2dda + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2e12 + iVar1) = param_2;
      return;
    }
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026dc14;
    }
    puVar3 = (undefined4 *)*puVar3;
  } while( true );
}

