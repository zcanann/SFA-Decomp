// Function: FUN_802b86b8
// Entry: 802b86b8
// Size: 428 bytes

void FUN_802b86b8(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  iVar5 = *(int *)(iVar3 + 0x40c);
  iVar4 = *(int *)(iVar1 + 0x4c);
  uVar2 = FUN_8002b9ec();
  (**(code **)(*DAT_803dcab8 + 0x14))(iVar1,uVar2,0x10,iVar5 + 0x1e,iVar5 + 0x20,iVar5 + 0x22);
  *(float *)(param_3 + 0x2c0) =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x22)) - DOUBLE_803e81a0);
  if (*(int *)(iVar1 + 0xf8) == 2) {
    (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
    *(undefined4 *)(iVar1 + 0xf8) = 1;
  }
  else if (*(int *)(iVar1 + 0xf8) == 3) {
    (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,0xffffffff);
    *(undefined4 *)(iVar1 + 0xf8) = 1;
  }
  else {
    FUN_8003b310(iVar1,iVar3 + 0x3ac);
    uVar2 = FUN_8002b9ec();
    *(undefined4 *)(param_3 + 0x2d0) = uVar2;
    iVar4 = *(int *)(iVar4 + 0x14);
    if ((0x49941 < iVar4) || (iVar4 < 0x4993f)) {
      (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e820c,iVar1,param_3,1);
    }
    *(undefined4 *)(iVar3 + 0x3e0) = *(undefined4 *)(iVar1 + 0xc0);
    *(undefined4 *)(iVar1 + 0xc0) = 0;
    (**(code **)(*DAT_803dca8c + 8))
              ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar1,param_3,&DAT_803db0dc,
               &DAT_803db0d0);
    *(undefined4 *)(iVar1 + 0xc0) = *(undefined4 *)(iVar3 + 0x3e0);
    FUN_802b8360(iVar1,iVar3);
  }
  FUN_80286128();
  return;
}

