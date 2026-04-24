// Function: FUN_802b8e18
// Entry: 802b8e18
// Size: 428 bytes

void FUN_802b8e18(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  iVar5 = *(int *)(iVar3 + 0x40c);
  iVar4 = *(int *)(uVar1 + 0x4c);
  uVar2 = FUN_8002bac4();
  (**(code **)(*DAT_803dd738 + 0x14))(uVar1,uVar2,0x10,iVar5 + 0x1e,iVar5 + 0x20,iVar5 + 0x22);
  *(float *)(param_3 + 0x2c0) =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x22)) - DOUBLE_803e8e38);
  if (*(int *)(uVar1 + 0xf8) == 2) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar1,0xffffffff);
    *(undefined4 *)(uVar1 + 0xf8) = 1;
  }
  else if (*(int *)(uVar1 + 0xf8) == 3) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar1,0xffffffff);
    *(undefined4 *)(uVar1 + 0xf8) = 1;
  }
  else {
    FUN_8003b408(uVar1,iVar3 + 0x3ac);
    uVar2 = FUN_8002bac4();
    *(undefined4 *)(param_3 + 0x2d0) = uVar2;
    iVar4 = *(int *)(iVar4 + 0x14);
    if ((0x49941 < iVar4) || (iVar4 < 0x4993f)) {
      (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e8ea4,uVar1,param_3,1);
    }
    *(undefined4 *)(iVar3 + 0x3e0) = *(undefined4 *)(uVar1 + 0xc0);
    *(undefined4 *)(uVar1 + 0xc0) = 0;
    (**(code **)(*DAT_803dd70c + 8))
              ((double)FLOAT_803dc074,(double)FLOAT_803dc074,uVar1,param_3,&DAT_803dbd3c,
               &DAT_803dbd30);
    *(undefined4 *)(uVar1 + 0xc0) = *(undefined4 *)(iVar3 + 0x3e0);
    FUN_802b8ac0(uVar1,iVar3);
  }
  FUN_8028688c();
  return;
}

