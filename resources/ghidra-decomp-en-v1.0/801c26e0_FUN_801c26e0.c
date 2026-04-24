// Function: FUN_801c26e0
// Entry: 801c26e0
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801c2714) */

undefined4 FUN_801c26e0(int param_1)

{
  int iVar1;
  int *piVar2;
  ushort *puVar3;
  double dVar4;
  
  puVar3 = *(ushort **)(param_1 + 0xb8);
  if (*(char *)((int)puVar3 + 3) == '\x01') {
    piVar2 = (int *)FUN_800394ac(param_1,0,0);
    if (piVar2 != (int *)0x0) {
      iVar1 = *piVar2 + (uint)DAT_803db410 * 0x10;
      if (0x100 < iVar1) {
        iVar1 = 0x100;
        *(undefined *)((int)puVar3 + 3) = 2;
      }
      *piVar2 = iVar1;
    }
  }
  else if (*(char *)((int)puVar3 + 3) == '\0') {
    iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x22));
    if (iVar1 != 0) {
      *(undefined *)((int)puVar3 + 3) = 1;
    }
  }
  else {
    piVar2 = (int *)FUN_800394ac(param_1,0,0);
    if (piVar2 != (int *)0x0) {
      *puVar3 = *puVar3 + (ushort)DAT_803db410 * 800;
      dVar4 = (double)FUN_80294204((double)((FLOAT_803e4e3c *
                                            (float)((double)CONCAT44(0x43300000,(uint)*puVar3) -
                                                   DOUBLE_803e4e48)) / FLOAT_803e4e40));
      *piVar2 = (int)-(FLOAT_803e4e34 * (float)((double)FLOAT_803e4e38 - dVar4) - FLOAT_803e4e30);
    }
  }
  return 0;
}

