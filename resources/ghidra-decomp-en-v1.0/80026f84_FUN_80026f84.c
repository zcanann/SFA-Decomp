// Function: FUN_80026f84
// Entry: 80026f84
// Size: 384 bytes

void FUN_80026f84(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint unaff_r27;
  uint unaff_r28;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  undefined8 uVar11;
  undefined4 local_38;
  undefined4 local_34 [13];
  
  uVar11 = FUN_802860c0();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  local_38 = param_4;
  local_34[0] = param_5;
  iVar2 = FUN_80022a48();
  uVar10 = 0;
  uVar9 = param_3;
  if ((uint)DAT_803db440 < (param_3 & 0xffff)) {
    uVar9 = (uint)DAT_803db440;
  }
  uVar8 = ((uVar9 & 0xffff) * 6 + 0x1f & 0xffe0) >> 5;
  FUN_800229f8(iVar2,iVar1,uVar8);
  uVar6 = 0;
  uVar3 = 0;
  while ((param_3 & 0xffff) != 0) {
    param_3 = param_3 - uVar9;
    if ((param_3 & 0xffff) != 0) {
      uVar5 = (uint)DAT_803db440;
      unaff_r28 = param_3;
      if (uVar5 < (param_3 & 0xffff)) {
        unaff_r28 = uVar5;
      }
      unaff_r27 = ((unaff_r28 & 0xffff) * 6 + 0x1f & 0xffe0) >> 5;
      FUN_800229f8(iVar2 + (uVar6 ^ 1) * 0x2000,iVar1 + ((uVar10 & 0xffff) + uVar5) * 6,unaff_r27);
      uVar3 = 1;
    }
    FUN_800229c4(uVar3);
    iVar4 = iVar2 + uVar6 * 0x2000;
    iVar7 = iVar4 + 0x1000;
    FUN_8002430c(iVar4,iVar7,uVar9,&local_38,local_34,param_6,uVar10);
    FUN_80022948((int)uVar11 + (uVar10 & 0xffff) * 6,iVar7,uVar8 & 0xffff);
    uVar10 = uVar10 + uVar9;
    uVar3 = 1;
    uVar6 = uVar6 ^ 1;
    uVar8 = unaff_r27;
    uVar9 = unaff_r28;
  }
  FUN_800229c4(0);
  FUN_8028610c();
  return;
}

