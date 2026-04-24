// Function: FUN_80023134
// Entry: 80023134
// Size: 388 bytes

void FUN_80023134(void)

{
  short sVar1;
  short sVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d8();
  iVar4 = (int)((ulonglong)uVar9 >> 0x20);
  iVar7 = (&DAT_803406a8)[iVar4 * 5];
  iVar8 = iVar7 + (int)uVar9 * 0x1c;
  sVar1 = *(short *)(iVar8 + 0xc);
  sVar2 = *(short *)(iVar8 + 10);
  *(undefined2 *)(iVar8 + 8) = 0;
  DAT_803dcb14 = DAT_803dcb14 + 1;
  piVar6 = (int *)(&DAT_803406b0 + iVar4 * 0x14);
  *piVar6 = *piVar6 - *(int *)(iVar8 + 4);
  if ((*piVar6 < 0) || ((int)(&DAT_803406ac)[iVar4 * 5] < *piVar6)) {
    FUN_8007d6dc(s__ERROR_free__memory_usage_value_c_802ca9cc);
  }
  if ((sVar1 != -1) && (iVar5 = iVar7 + sVar1 * 0x1c, *(short *)(iVar5 + 8) == 0)) {
    *(int *)(iVar8 + 4) = *(int *)(iVar8 + 4) + *(int *)(iVar5 + 4);
    sVar3 = *(short *)(iVar5 + 0xc);
    *(short *)(iVar8 + 0xc) = sVar3;
    if (sVar3 != -1) {
      *(short *)(iVar7 + sVar3 * 0x1c + 10) = (short)uVar9;
    }
    iVar5 = (&DAT_803406a4)[iVar4 * 5];
    (&DAT_803406a4)[iVar4 * 5] = iVar5 + -1;
    *(short *)(iVar7 + (iVar5 + -1) * 0x1c + 0xe) = sVar1;
  }
  if ((sVar2 != -1) && (iVar5 = iVar7 + sVar2 * 0x1c, *(short *)(iVar5 + 8) == 0)) {
    *(int *)(iVar5 + 4) = *(int *)(iVar5 + 4) + *(int *)(iVar8 + 4);
    sVar1 = *(short *)(iVar8 + 0xc);
    *(short *)(iVar5 + 0xc) = sVar1;
    if (sVar1 != -1) {
      *(short *)(iVar7 + sVar1 * 0x1c + 10) = sVar2;
    }
    iVar8 = (&DAT_803406a4)[iVar4 * 5];
    (&DAT_803406a4)[iVar4 * 5] = iVar8 + -1;
    *(short *)(iVar7 + (iVar8 + -1) * 0x1c + 0xe) = (short)uVar9;
  }
  FUN_80286124();
  return;
}

