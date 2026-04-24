// Function: FUN_801b62fc
// Entry: 801b62fc
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x801b64b0) */
/* WARNING: Removing unreachable block (ram,0x801b64a8) */
/* WARNING: Removing unreachable block (ram,0x801b6314) */
/* WARNING: Removing unreachable block (ram,0x801b630c) */

void FUN_801b62fc(void)

{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  double dVar9;
  undefined8 uVar10;
  undefined8 local_58;
  undefined8 local_50;
  
  uVar10 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  piVar2 = (int *)FUN_8002b660(iVar1);
  iVar6 = *piVar2;
  for (iVar7 = 0; uVar8 = (uint)*(ushort *)(iVar6 + 0xe4), iVar7 < (int)uVar8; iVar7 = iVar7 + 1) {
    puVar3 = (undefined2 *)FUN_80028568((int)piVar2,iVar7);
    psVar4 = (short *)FUN_800284d8(iVar6,iVar7);
    if (*psVar4 < 1) {
      dVar9 = (double)FUN_802945e0();
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e569c * dVar9 -
                                    (double)(float)(local_50 - DOUBLE_803e56a8));
    }
    else {
      dVar9 = (double)FUN_802945e0();
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e569c * dVar9 +
                            (double)(float)(local_58 - DOUBLE_803e56a8));
    }
  }
  uVar5 = FUN_80028568((int)piVar2,0);
  FUN_80242114(uVar5,uVar8 * 6);
  *(undefined *)(iVar1 + 0x36) = *(undefined *)((int)uVar10 + 0x51);
  FUN_80286880();
  return;
}

