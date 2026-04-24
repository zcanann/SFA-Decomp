// Function: FUN_8021b178
// Entry: 8021b178
// Size: 276 bytes

void FUN_8021b178(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  int *piVar10;
  int local_28 [10];
  
  iVar4 = FUN_802860d4();
  piVar10 = *(int **)(iVar4 + 0xb8);
  iVar4 = *(int *)(iVar4 + 0x4c);
  if ((*(short *)(iVar4 + 0x1a) != 0) && (*piVar10 == 0)) {
    piVar5 = (int *)FUN_80036f50(0x17,local_28);
    while( true ) {
      iVar2 = local_28[0] + -1;
      bVar1 = local_28[0] == 0;
      local_28[0] = iVar2;
      if (bVar1) break;
      iVar7 = *(int *)(*piVar5 + 0x4c);
      iVar9 = 0;
      piVar8 = piVar10;
      for (iVar2 = 0; iVar2 < piVar10[5]; iVar2 = iVar2 + 1) {
        if ((uint)*(byte *)(iVar7 + 0x18) == *(short *)(iVar4 + 0x1a) + iVar9) {
          *piVar8 = *piVar5;
          (**(code **)(*DAT_803dca54 + 0x48))(0,*piVar8,0xffffffff);
        }
        iVar9 = iVar9 + 4;
        piVar8 = piVar8 + 1;
      }
      piVar5 = piVar5 + 1;
    }
  }
  if (*(char *)((int)piVar10 + 0x1a) < '\0') {
    uVar6 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1e));
    uVar3 = countLeadingZeros(uVar6);
    *(byte *)((int)piVar10 + 0x1a) =
         (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)piVar10 + 0x1a) & 0x7f;
  }
  FUN_80286120();
  return;
}

