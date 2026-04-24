// Function: FUN_80035728
// Entry: 80035728
// Size: 192 bytes

void FUN_80035728(int param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 uStack_18;
  undefined4 auStack_14 [4];
  
  piVar2 = (int *)FUN_8002e1f4(&uStack_18,auStack_14);
  DAT_803dd860 = 0;
  if (0 < param_1) {
    do {
      puVar3 = *(undefined4 **)(*piVar2 + 0x54);
      if (((puVar3 != (undefined4 *)0x0) && ((*(ushort *)(puVar3 + 0x18) & 1) != 0)) &&
         ((*(byte *)((int)puVar3 + 0x62) & 8) != 0)) {
        if (DAT_803dd860 < 0x32) {
          iVar1 = DAT_803dd860 * 4;
          DAT_803dd860 = DAT_803dd860 + 1;
          *(int *)(DAT_803dd864 + iVar1) = *piVar2;
        }
        *puVar3 = 0;
        *(ushort *)(puVar3 + 0x18) = *(ushort *)(puVar3 + 0x18) & 0xfff7;
        *(undefined2 *)(puVar3 + 0x16) = 0x400;
      }
      piVar2 = piVar2 + 1;
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  return;
}

