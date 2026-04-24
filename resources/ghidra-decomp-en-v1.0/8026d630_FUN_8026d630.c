// Function: FUN_8026d630
// Entry: 8026d630
// Size: 180 bytes

void FUN_8026d630(uint param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  for (puVar2 = DAT_803de234; puVar3 = DAT_803de230, puVar2 != (undefined4 *)0x0;
      puVar2 = (undefined4 *)*puVar2) {
    if (puVar2[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar2 + 9);
      goto LAB_8026d698;
    }
  }
  do {
    if (puVar3 == (undefined4 *)0x0) {
      uVar4 = 0xffffffff;
LAB_8026d698:
      if (uVar4 == 0xffffffff) {
        return;
      }
      if ((uVar4 & 0x80000000) != 0) {
        iVar1 = (uVar4 & 0x7fffffff) * 0x1868;
        (&DAT_803b182a)[iVar1] = (&DAT_803b182a)[iVar1] | 0x10;
        *(undefined4 *)(&DAT_803b1820 + iVar1) = param_2;
        *(undefined4 *)(&DAT_803b1824 + iVar1) = param_3;
        return;
      }
      *(undefined4 *)(&DAT_803b0a6c + uVar4 * 0x1868) = param_2;
      *(undefined4 *)(&DAT_803b0a70 + uVar4 * 0x1868) = param_3;
      return;
    }
    if (puVar3[3] == (param_1 & 0x7fffffff)) {
      uVar4 = param_1 & 0x80000000 | (uint)*(byte *)((int)puVar3 + 9);
      goto LAB_8026d698;
    }
    puVar3 = (undefined4 *)*puVar3;
  } while( true );
}

