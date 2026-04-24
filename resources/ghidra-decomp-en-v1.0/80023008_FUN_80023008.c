// Function: FUN_80023008
// Entry: 80023008
// Size: 300 bytes

void FUN_80023008(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_802860d0();
  iVar5 = (int)((ulonglong)uVar11 >> 0x20);
  iVar8 = (int)uVar11;
  iVar7 = (&DAT_803406a8)[iVar5 * 5];
  iVar10 = iVar8 * 0x1c;
  iVar4 = iVar7 + iVar10;
  *(undefined2 *)(iVar4 + 8) = param_4;
  iVar9 = *(int *)(iVar4 + 4);
  *(int *)(iVar4 + 4) = param_3;
  *(undefined4 *)(iVar4 + 0x10) = param_6;
  if (param_3 < iVar9) {
    iVar4 = (&DAT_803406a4)[iVar5 * 5];
    (&DAT_803406a4)[iVar5 * 5] = iVar4 + 1;
    sVar1 = *(short *)(iVar7 + iVar4 * 0x1c + 0xe);
    iVar8 = (int)sVar1;
    piVar6 = (int *)(iVar7 + iVar8 * 0x1c);
    *piVar6 = *(int *)(iVar7 + iVar10) + param_3;
    iVar5 = *piVar6;
    uVar3 = iVar5 >> 0x1f;
    if ((uVar3 * 0x20 | iVar5 * 0x8000000 + uVar3 >> 0x1b) != uVar3) {
      FUN_8007d6dc(s_SPAWNED_A_SLOT_NOT_ALIGNED_TO_32_802ca97c,(int)*(short *)((int)piVar6 + 0xe),
                   iVar5,piVar6[1]);
    }
    iVar5 = iVar7 + iVar8 * 0x1c;
    *(int *)(iVar5 + 4) = iVar9 - param_3;
    *(undefined2 *)(iVar5 + 8) = param_5;
    sVar2 = *(short *)(iVar7 + iVar10 + 0xc);
    *(short *)(iVar5 + 0xc) = sVar2;
    *(short *)(iVar5 + 10) = (short)uVar11;
    *(short *)(iVar7 + iVar10 + 0xc) = sVar1;
    if (sVar2 != -1) {
      *(short *)(iVar7 + sVar2 * 0x1c + 10) = sVar1;
    }
    *(undefined4 *)(iVar7 + iVar10 + 0x14) = DAT_803dcb1c;
  }
  FUN_8028611c(iVar8);
  return;
}

