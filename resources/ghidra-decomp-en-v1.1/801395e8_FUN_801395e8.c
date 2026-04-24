// Function: FUN_801395e8
// Entry: 801395e8
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x80139704) */
/* WARNING: Removing unreachable block (ram,0x801396fc) */
/* WARNING: Removing unreachable block (ram,0x80139600) */
/* WARNING: Removing unreachable block (ram,0x801395f8) */

void FUN_801395e8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  dVar7 = (double)FLOAT_803e30a8;
  iVar4 = 0;
  iVar3 = 0;
  iVar2 = iVar1;
  dVar8 = dVar7;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0x798); iVar5 = iVar5 + 1) {
    if ((int)*(char *)(iVar2 + 0x74d) == (int)uVar9) {
      dVar6 = FUN_80021730((float *)(*(int *)(iVar1 + 4) + 0x18),
                           (float *)(*(int *)(iVar2 + 0x748) + 0x18));
      if (*(char *)(iVar2 + 0x74c) == '\x01') {
        if (dVar6 < dVar8) {
          iVar4 = *(int *)(iVar2 + 0x748);
          dVar8 = dVar6;
        }
      }
      else if (dVar6 < dVar7) {
        iVar3 = *(int *)(iVar2 + 0x748);
        dVar7 = dVar6;
      }
    }
    iVar2 = iVar2 + 8;
  }
  if (iVar4 == 0) {
    if (iVar3 == 0) goto LAB_801396fc;
    *(int *)(iVar1 + 0x24) = iVar3;
  }
  else {
    *(int *)(iVar1 + 0x24) = iVar4;
  }
  iVar2 = *(int *)(iVar1 + 0x24) + 0x18;
  if (*(int *)(iVar1 + 0x28) != iVar2) {
    *(int *)(iVar1 + 0x28) = iVar2;
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) & 0xfffffbff;
    *(undefined2 *)(iVar1 + 0xd2) = 0;
  }
  *(undefined *)(iVar1 + 10) = 0;
LAB_801396fc:
  FUN_80286888();
  return;
}

