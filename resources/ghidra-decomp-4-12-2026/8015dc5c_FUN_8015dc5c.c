// Function: FUN_8015dc5c
// Entry: 8015dc5c
// Size: 504 bytes

void FUN_8015dc5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  
  iVar7 = *(int *)(param_9 + 0xb8);
  iVar6 = *(int *)(param_9 + 0x4c);
  if (*(int *)(param_9 + 0xf4) == 0) {
    if (*(int *)(param_9 + 0xf8) == 0) {
      *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar6 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar6 + 0x2e),param_9,0xffffffff);
      *(undefined4 *)(param_9 + 0xf8) = 1;
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x30))(param_9,iVar7,0);
      if (iVar1 == 0) {
        *(undefined2 *)(iVar7 + 0x402) = 0;
      }
      else {
        uVar8 = FUN_8015d86c(param_9,iVar7,iVar7);
        FUN_8015d07c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        if (*(short *)(iVar7 + 0x402) == 0) {
          FUN_8015d544(param_9,iVar7,iVar7);
        }
        else {
          FUN_8015d728(param_9,iVar7,iVar7);
        }
        if ((*(byte *)(iVar7 + 0x404) & 2) != 0) {
          *(float *)(param_9 + 0x10) = *(float *)(iVar6 + 0xc) - FLOAT_803e3a28;
        }
      }
    }
  }
  else if (((*(short *)(iVar7 + 0x270) != 3) || ((*(byte *)(iVar7 + 0x404) & 1) != 0)) &&
          (iVar1 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar6 + 0x14)), iVar1 != 0))
  {
    uVar2 = 0xe;
    uVar3 = 8;
    uVar4 = 0x102;
    uVar5 = 0x26;
    iVar1 = *DAT_803dd738;
    (**(code **)(iVar1 + 0x58))((double)FLOAT_803e3a50,param_9,iVar6,iVar7);
    *(undefined2 *)(iVar7 + 0x402) = 0;
    FUN_8000bb38(param_9,0x263);
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0x10,uVar2,uVar3,uVar4,uVar5,iVar1);
    *(undefined *)(iVar7 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return;
}

