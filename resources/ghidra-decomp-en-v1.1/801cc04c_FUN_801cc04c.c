// Function: FUN_801cc04c
// Entry: 801cc04c
// Size: 636 bytes

void FUN_801cc04c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  iVar1 = FUN_80286840();
  iVar3 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_11 + 0x6e) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  uVar4 = extraout_f1;
  if (*(short *)(iVar3 + 10) != 0) {
    *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + *(short *)(iVar3 + 10);
    if ((*(short *)(iVar3 + 8) < 2) && (*(short *)(iVar3 + 10) < 1)) {
      *(undefined2 *)(iVar3 + 8) = 1;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar3 + 8)) && (-1 < *(short *)(iVar3 + 10))) {
      *(undefined2 *)(iVar3 + 8) = 0x46;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    uVar4 = (**(code **)(*DAT_803dd6f0 + 0x38))(3,*(ushort *)(iVar3 + 8) & 0xff);
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    switch(*(undefined *)(param_11 + iVar2 + 0x81)) {
    case 1:
      uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                           ,0xc3,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      if (DAT_803dc270 == 0xffffffff) {
        uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,0x14,0,param_13,param_14,param_15,param_16);
      }
      else {
        uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,DAT_803dc270 & 0xffff,0,param_13,param_14,param_15,param_16);
      }
      break;
    case 3:
      *(undefined *)(iVar3 + 0x14) = 1;
      break;
    case 4:
      *(undefined *)(iVar3 + 0x13) = 4;
      *(undefined *)(iVar3 + 0x14) = 2;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0x1d2,0);
      uVar4 = FUN_800201ac(0x126,1);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar3 + 0x13) = 6;
      *(undefined *)(iVar3 + 0x14) = 3;
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      uVar4 = FUN_800201ac(0x129,1);
      break;
    case 6:
      uVar4 = FUN_800201ac(0x1d2,1);
      break;
    case 7:
      uVar4 = FUN_800201ac(0x1d2,0);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 8:
      uVar4 = FUN_800201ac(0x127,1);
      break;
    case 9:
      uVar4 = FUN_800201ac(0x128,1);
      if (DAT_803de860 == 0) {
        DAT_803de860 = FUN_80056818();
      }
      break;
    case 0xb:
      *(undefined2 *)(iVar3 + 8) = 100;
      param_13 = 0;
      param_14 = *DAT_803dd6f0;
      uVar4 = (**(code **)(param_14 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar3 + 8) & 0xff);
    }
    *(undefined *)(param_11 + iVar2 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

