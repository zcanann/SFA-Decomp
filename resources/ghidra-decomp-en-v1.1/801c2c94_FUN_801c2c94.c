// Function: FUN_801c2c94
// Entry: 801c2c94
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801c2cc8) */

undefined4 FUN_801c2c94(int param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  
  psVar4 = *(short **)(param_1 + 0xb8);
  if (*(char *)((int)psVar4 + 3) == '\x01') {
    piVar2 = (int *)FUN_800395a4(param_1,0);
    if (piVar2 != (int *)0x0) {
      iVar3 = *piVar2 + (uint)DAT_803dc070 * 0x10;
      if (0x100 < iVar3) {
        iVar3 = 0x100;
        *(undefined *)((int)psVar4 + 3) = 2;
      }
      *piVar2 = iVar3;
    }
  }
  else if (*(char *)((int)psVar4 + 3) == '\0') {
    uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x22));
    if (uVar1 != 0) {
      *(undefined *)((int)psVar4 + 3) = 1;
    }
  }
  else {
    piVar2 = (int *)FUN_800395a4(param_1,0);
    if (piVar2 != (int *)0x0) {
      *psVar4 = *psVar4 + (ushort)DAT_803dc070 * 800;
      dVar5 = (double)FUN_80294964();
      *piVar2 = (int)-(FLOAT_803e5acc * (float)((double)FLOAT_803e5ad0 - dVar5) - FLOAT_803e5ac8);
    }
  }
  return 0;
}

