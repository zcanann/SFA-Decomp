// Function: FUN_800271bc
// Entry: 800271bc
// Size: 236 bytes

void FUN_800271bc(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  undefined auStack72 [72];
  
  uVar9 = FUN_802860d8();
  piVar2 = (int *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar8 = *piVar2;
  iVar6 = 0;
  for (uVar7 = 0; uVar7 < *(byte *)(iVar8 + 0xf3); uVar7 = uVar7 + 1) {
    uVar4 = (uint)*(byte *)(*piVar2 + 0xf3);
    if (uVar4 == 0) {
      iVar1 = 1;
    }
    else {
      iVar1 = uVar4 + *(byte *)(*piVar2 + 0xf4);
    }
    uVar4 = uVar7;
    if (iVar1 <= (int)uVar7) {
      uVar4 = 0;
    }
    iVar1 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3];
    iVar3 = *(int *)(iVar8 + 0x3c) + iVar6;
    FUN_802472e4(-(double)*(float *)(iVar3 + 0x10),-(double)*(float *)(iVar3 + 0x14),
                 -(double)*(float *)(iVar3 + 0x18),auStack72);
    FUN_80246eb4(iVar1 + uVar4 * 0x40,auStack72,auStack72);
    FUN_802479d0(auStack72,iVar5);
    iVar6 = iVar6 + 0x1c;
    iVar5 = iVar5 + 0x30;
  }
  FUN_80286124();
  return;
}

