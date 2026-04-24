// Function: FUN_80027048
// Entry: 80027048
// Size: 384 bytes

void FUN_80027048(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,int param_8)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  uint uVar6;
  short *psVar7;
  uint unaff_r27;
  uint unaff_r28;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  undefined8 uVar11;
  undefined4 local_38;
  undefined4 local_34 [13];
  
  uVar11 = FUN_80286824();
  uVar1 = (uint)((ulonglong)uVar11 >> 0x20);
  local_38 = param_4;
  local_34[0] = param_5;
  uVar2 = FUN_80022b0c();
  uVar10 = 0;
  uVar9 = param_3;
  if ((uint)DAT_803dc0a0 < (param_3 & 0xffff)) {
    uVar9 = (uint)DAT_803dc0a0;
  }
  uVar8 = ((uVar9 & 0xffff) * 6 + 0x1f & 0xffe0) >> 5;
  FUN_80022abc(uVar2,uVar1,uVar8);
  uVar6 = 0;
  iVar3 = 0;
  while ((param_3 & 0xffff) != 0) {
    param_3 = param_3 - uVar9;
    if ((param_3 & 0xffff) != 0) {
      uVar5 = (uint)DAT_803dc0a0;
      unaff_r28 = param_3;
      if (uVar5 < (param_3 & 0xffff)) {
        unaff_r28 = uVar5;
      }
      unaff_r27 = ((unaff_r28 & 0xffff) * 6 + 0x1f & 0xffe0) >> 5;
      FUN_80022abc(uVar2 + (uVar6 ^ 1) * 0x2000,uVar1 + ((uVar10 & 0xffff) + uVar5) * 6,unaff_r27);
      iVar3 = 1;
    }
    FUN_80022a88(iVar3);
    psVar4 = (short *)(uVar2 + uVar6 * 0x2000);
    psVar7 = psVar4 + 0x800;
    FUN_800243d0(psVar4,(undefined4 *)psVar7,uVar9,&local_38,local_34,param_6,uVar10,param_8);
    FUN_80022a0c((int)uVar11 + (uVar10 & 0xffff) * 6,(uint)psVar7,uVar8 & 0xffff);
    uVar10 = uVar10 + uVar9;
    iVar3 = 1;
    uVar6 = uVar6 ^ 1;
    uVar8 = unaff_r27;
    uVar9 = unaff_r28;
  }
  FUN_80022a88(0);
  FUN_80286870();
  return;
}

