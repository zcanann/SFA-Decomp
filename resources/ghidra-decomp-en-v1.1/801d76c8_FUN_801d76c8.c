// Function: FUN_801d76c8
// Entry: 801d76c8
// Size: 912 bytes

void FUN_801d76c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int *piVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  
  iVar2 = FUN_80286840();
  piVar8 = *(int **)(iVar2 + 0xb8);
  iVar7 = param_11;
  uVar9 = extraout_f1;
  iVar3 = FUN_800805cc(param_11);
  if (iVar3 == 0x35f) {
    FUN_800805ec(param_11,0x2648);
    iVar3 = FUN_8001496c();
    if (iVar3 != 0x10) {
      uVar9 = FUN_80014974(0x10);
    }
  }
  if (*piVar8 != 0) {
    param_2 = (double)FLOAT_803dc074;
    uVar9 = FUN_8002fb40((double)(*(float *)(iVar2 + 0x98) - *(float *)(*piVar8 + 0x98)),param_2);
  }
  *(code **)(param_11 + 0xec) = FUN_801d7388;
  *(code **)(param_11 + 0xe8) = FUN_801d76a4;
  if (*(char *)(param_11 + 0x56) != '\0') {
    *(byte *)((int)piVar8 + 10) = *(byte *)((int)piVar8 + 10) & 0xfc;
    iVar3 = FUN_801d7348();
    if (iVar3 != 0) {
      *(byte *)((int)piVar8 + 10) = *(byte *)((int)piVar8 + 10) | 1;
    }
    uVar4 = FUN_80020078(0x2e8);
    if (uVar4 == 0) {
      uVar4 = FUN_80020078(0x123);
      if (uVar4 == 0) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      *(byte *)((int)piVar8 + 10) = *(byte *)((int)piVar8 + 10) | 2;
    }
    *(undefined *)(param_11 + 0x56) = 0;
    uVar4 = FUN_80020078((int)*(short *)((int)piVar8 + 0xe));
    if ((uVar4 != 0) && (iVar3 = FUN_800805cc(param_11), iVar3 == 0x35f)) {
      FUN_8000d0e0();
      FUN_80080474();
      uVar9 = FUN_8000cf74();
      *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
    }
  }
  iVar3 = 0;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar3) {
      FUN_801d6f04(iVar2);
      FUN_8028688c();
      return;
    }
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 3:
      *(undefined *)(piVar8 + 2) = 0;
      break;
    case 4:
      *(undefined *)(piVar8 + 2) = 1;
      break;
    case 6:
      FUN_80130124(0);
      uVar9 = FUN_80014974(1);
      uVar9 = FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7e,'\x01'
                           ,iVar7,param_12,param_13,param_14,param_15,param_16);
      break;
    case 7:
      FUN_80130124(0);
      FUN_80014974(1);
      uVar9 = FUN_800201ac(0x884,1);
      uVar9 = FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7e,'\x01'
                           ,iVar7,param_12,param_13,param_14,param_15,param_16);
      break;
    case 9:
      (**(code **)(*DAT_803dd72c + 0x44))(0x17,1);
      iVar7 = *DAT_803dd72c;
      (**(code **)(iVar7 + 0x44))(0xe,2);
      FUN_80130124(0);
      uVar9 = FUN_80014974(1);
      break;
    case 10:
      *(byte *)((int)piVar8 + 9) = *(byte *)((int)piVar8 + 9) ^ 1;
      break;
    case 0xc:
      FUN_80130124(0);
      uVar9 = FUN_80014974(1);
      uVar9 = FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x33,'\0',
                           iVar7,param_12,param_13,param_14,param_15,param_16);
      break;
    case 0xd:
      FUN_8001b7b4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
      iVar5 = FUN_8001496c();
      if (iVar5 == 0x10) {
        piVar6 = (int *)FUN_80014964();
        (**(code **)(*piVar6 + 0x10))(*(byte *)(param_11 + iVar3 + 0x81) - 0xd);
      }
      FUN_800201ac((int)*(short *)((int)piVar8 + 0xe),1);
      uVar9 = FUN_800201ac(0x887,1);
      break;
    case 0x12:
      iVar7 = 0;
      param_12 = *DAT_803dd72c;
      uVar9 = (**(code **)(param_12 + 0x50))(7,10);
      break;
    case 0x14:
      iVar7 = 1;
      FUN_80043604(0,0,1);
      break;
    case 0x15:
      iVar7 = 1;
      FUN_80043604(0,0,1);
      FUN_8004832c(0x42);
      uVar9 = FUN_80043938(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      break;
    case 0x16:
      iVar7 = 1;
      FUN_80043604(0,0,1);
      FUN_8004832c(0x42);
      uVar9 = FUN_80043938(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      break;
    case 0x17:
      *(byte *)(piVar8 + 0x35) = *(byte *)(piVar8 + 0x35) | 4;
      uVar9 = FUN_8000bb38(0,0x420);
    }
    iVar3 = iVar3 + 1;
  } while( true );
}

