// Function: FUN_8015f540
// Entry: 8015f540
// Size: 836 bytes

void FUN_8015f540(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  undefined auStack_28 [40];
  
  uVar1 = FUN_80286840();
  iVar9 = *(int *)(uVar1 + 0xb8);
  iVar8 = *(int *)(uVar1 + 0x4c);
  if (*(int *)(uVar1 + 0xf4) == 0) {
    if (*(int *)(uVar1 + 0xf8) == 0) {
      *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
      *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar8 + 0x2e),uVar1,0xffffffff);
      *(undefined4 *)(uVar1 + 0xf8) = 1;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dd738 + 0x30))(uVar1,iVar9,0);
      if (iVar2 == 0) {
        *(undefined2 *)(iVar9 + 0x402) = 0;
      }
      else if (((*(byte *)(iVar9 + 0x404) & 0x10) == 0) ||
              (iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28), iVar2 != 0)) {
        uVar10 = FUN_8015f1c8(uVar1,iVar9,iVar9);
        if (*(short *)(iVar9 + 0x402) == 0) {
          FUN_8015f018(uVar1,iVar9,iVar9);
        }
        else {
          iVar2 = *(int *)(iVar9 + 0x40c);
          if ((*(byte *)(iVar2 + 8) & 1) != 0) {
            FUN_8015eef4(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,iVar9)
            ;
          }
          if ((*(byte *)(iVar2 + 8) & 2) != 0) {
            (**(code **)(*DAT_803dd708 + 8))(uVar1,0x345,0,1,0xffffffff,0);
          }
          if ((*(byte *)(iVar2 + 8) & 4) != 0) {
            iVar7 = 0;
            do {
              (**(code **)(*DAT_803dd708 + 8))(uVar1,0x343,0,1,0xffffffff,0);
              iVar7 = iVar7 + 1;
            } while (iVar7 < 10);
          }
          *(undefined *)(iVar2 + 8) = 0;
          (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3a60,uVar1,iVar9,0xffffffff);
          (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,uVar1,iVar9,4);
          *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(uVar1 + 0xc0);
          *(undefined4 *)(uVar1 + 0xc0) = 0;
          (**(code **)(*DAT_803dd70c + 8))
                    ((double)FLOAT_803dc074,(double)FLOAT_803dc074,uVar1,iVar9,&DAT_803ad210,
                     &DAT_803ad1f8);
          *(undefined4 *)(uVar1 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
        }
        *(float *)(uVar1 + 0x10) = *(float *)(iVar8 + 0xc) - FLOAT_803e3ab0;
      }
      else {
        *(undefined2 *)(iVar9 + 0x402) = 0;
      }
    }
  }
  else if (((*(short *)(iVar9 + 0x270) != 3) || ((*(byte *)(iVar9 + 0x404) & 1) != 0)) &&
          (iVar2 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar2 != 0))
  {
    uVar3 = 7;
    uVar4 = 6;
    uVar5 = 0x102;
    uVar6 = 0x26;
    iVar2 = *DAT_803dd738;
    (**(code **)(iVar2 + 0x58))((double)FLOAT_803e3aac,uVar1,iVar8,iVar9);
    *(undefined2 *)(iVar9 + 0x402) = 0;
    FUN_8000bb38(uVar1,0x263);
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,8,0x10,uVar3,uVar4,uVar5,uVar6,iVar2);
    *(undefined *)(iVar9 + 0x346) = 0;
    *(undefined *)(uVar1 + 0x36) = 0xff;
    *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  }
  FUN_8028688c();
  return;
}

