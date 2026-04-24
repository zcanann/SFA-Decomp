// Function: FUN_800272a8
// Entry: 800272a8
// Size: 348 bytes

void FUN_800272a8(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined auStack88 [88];
  
  uVar8 = FUN_802860d4();
  piVar2 = (int *)((ulonglong)uVar8 >> 0x20);
  iVar6 = *piVar2;
  if (*(char *)(iVar6 + 0xf3) == '\0') {
    FUN_80246eb4((int)uVar8,piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3],
                 piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3]);
  }
  else {
    iVar7 = 0;
    for (uVar5 = 0; uVar5 < *(byte *)(iVar6 + 0xf3); uVar5 = uVar5 + 1) {
      uVar3 = (uint)*(byte *)(*piVar2 + 0xf3);
      if (uVar3 == 0) {
        iVar1 = 1;
      }
      else {
        iVar1 = uVar3 + *(byte *)(*piVar2 + 0xf4);
      }
      uVar3 = uVar5;
      if (iVar1 <= (int)uVar5) {
        uVar3 = 0;
      }
      iVar4 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + uVar3 * 0x40;
      iVar1 = *(int *)(iVar6 + 0x3c) + iVar7;
      FUN_802472e4(-(double)*(float *)(iVar1 + 0x10),-(double)*(float *)(iVar1 + 0x14),
                   -(double)*(float *)(iVar1 + 0x18),auStack88);
      FUN_80246eb4(iVar4,auStack88,auStack88);
      FUN_802479d0(auStack88,param_3);
      FUN_80246eb4((int)uVar8,iVar4,iVar4);
      iVar7 = iVar7 + 0x1c;
      param_3 = param_3 + 0x30;
    }
  }
  FUN_80286120();
  return;
}

