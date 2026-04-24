// Function: FUN_8021b820
// Entry: 8021b820
// Size: 276 bytes

void FUN_8021b820(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int *piVar9;
  int local_28 [10];
  
  iVar3 = FUN_80286838();
  piVar9 = *(int **)(iVar3 + 0xb8);
  iVar3 = *(int *)(iVar3 + 0x4c);
  if ((*(short *)(iVar3 + 0x1a) != 0) && (*piVar9 == 0)) {
    piVar4 = FUN_80037048(0x17,local_28);
    while (iVar2 = local_28[0] + -1, bVar1 = local_28[0] != 0, local_28[0] = iVar2, bVar1) {
      iVar6 = *(int *)(*piVar4 + 0x4c);
      iVar8 = 0;
      piVar7 = piVar9;
      for (iVar2 = 0; iVar2 < piVar9[5]; iVar2 = iVar2 + 1) {
        if ((uint)*(byte *)(iVar6 + 0x18) == *(short *)(iVar3 + 0x1a) + iVar8) {
          *piVar7 = *piVar4;
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,*piVar7,0xffffffff);
        }
        iVar8 = iVar8 + 4;
        piVar7 = piVar7 + 1;
      }
      piVar4 = piVar4 + 1;
    }
  }
  if (*(char *)((int)piVar9 + 0x1a) < '\0') {
    uVar5 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
    uVar5 = countLeadingZeros(uVar5);
    *(byte *)((int)piVar9 + 0x1a) =
         (byte)((uVar5 >> 5 & 0xff) << 7) | *(byte *)((int)piVar9 + 0x1a) & 0x7f;
  }
  FUN_80286884();
  return;
}

