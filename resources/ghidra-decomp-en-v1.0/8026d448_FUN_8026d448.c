// Function: FUN_8026d448
// Entry: 8026d448
// Size: 220 bytes

void FUN_8026d448(uint param_1,undefined2 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  for (puVar2 = DAT_803de234; puVar3 = DAT_803de230, puVar2 != (undefined4 *)0x0;
      puVar2 = (undefined4 *)*puVar2) {
    if (puVar2[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar2 + 9);
      goto LAB_8026d4b0;
    }
  }
  do {
    if (puVar3 == (undefined4 *)0x0) {
      uVar4 = 0xffffffff;
LAB_8026d4b0:
      if ((uVar4 & 0x80000000) != 0) {
        iVar1 = (uVar4 & 0x7fffffff) * 0x1868;
        (&DAT_803b182a)[iVar1] = (&DAT_803b182a)[iVar1] | 0x20;
        *(undefined2 *)(&DAT_803b1828 + iVar1) = param_2;
        return;
      }
      iVar1 = uVar4 * 0x1868;
      *(undefined2 *)(&DAT_803b1e6a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1ea2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1eda + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1f12 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1f4a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1f82 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1fba + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b1ff2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b202a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2062 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b209a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b20d2 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b210a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b2142 + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b217a + iVar1) = param_2;
      *(undefined2 *)(&DAT_803b21b2 + iVar1) = param_2;
      return;
    }
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026d4b0;
    }
    puVar3 = (undefined4 *)*puVar3;
  } while( true );
}

