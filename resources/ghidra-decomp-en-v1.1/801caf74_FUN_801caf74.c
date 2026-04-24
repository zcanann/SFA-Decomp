// Function: FUN_801caf74
// Entry: 801caf74
// Size: 788 bytes

void FUN_801caf74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  
  iVar1 = FUN_80286840();
  iVar4 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  uVar5 = extraout_f1;
  if (*(short *)(iVar4 + 10) != 0) {
    *(short *)(iVar4 + 8) = *(short *)(iVar4 + 8) + *(short *)(iVar4 + 10);
    if ((*(short *)(iVar4 + 8) < 2) && (*(short *)(iVar4 + 10) < 1)) {
      *(undefined2 *)(iVar4 + 8) = 1;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar4 + 8)) && (-1 < *(short *)(iVar4 + 10))) {
      *(undefined2 *)(iVar4 + 8) = 0x46;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    uVar5 = (**(code **)(*DAT_803dd6f0 + 0x38))(3,*(ushort *)(iVar4 + 8) & 0xff);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                           ,0xc3,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      if (DAT_803dc270 == 0xffffffff) {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,0x14,0,param_13,param_14,param_15,param_16);
      }
      else {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,DAT_803dc270 & 0xffff,0,param_13,param_14,param_15,param_16);
      }
      break;
    case 3:
      *(undefined *)(iVar4 + 0x10) = 1;
      break;
    case 4:
      *(undefined *)(iVar4 + 0xf) = 4;
      *(undefined *)(iVar4 + 0x10) = 2;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0x1cf,0);
      uVar5 = FUN_800201ac(0x126,1);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar4 + 0x10) = 3;
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      uVar5 = FUN_800201ac(0x129,1);
      break;
    case 6:
      uVar5 = FUN_800201ac(0x1cf,1);
      break;
    case 7:
      uVar5 = FUN_800201ac(0x1cf,0);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 8:
      uVar5 = FUN_800201ac(0x127,1);
      break;
    case 9:
      uVar5 = FUN_800201ac(0x128,1);
      if (DAT_803de858 == 0) {
        DAT_803de858 = FUN_80056818();
      }
      break;
    case 10:
      *(undefined2 *)(iVar4 + 8) = 100;
      param_13 = 0;
      param_14 = *DAT_803dd6f0;
      uVar5 = (**(code **)(param_14 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar4 + 8) & 0xff);
      break;
    case 0xb:
      *(undefined *)(iVar4 + 0xf) = 7;
    }
    *(undefined *)(param_11 + iVar3 + 0x81) = 0;
  }
  if (*(char *)(iVar4 + 0xf) == '\a') {
    uVar2 = FUN_80014f14(0);
    if ((uVar2 & 0x100) == 0) {
      uVar2 = FUN_80014f14(0);
      if ((uVar2 & 0x200) != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
        *(undefined *)(iVar4 + 0xf) = 7;
        *(undefined2 *)(iVar4 + 2) = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
      *(undefined *)(iVar4 + 0xf) = 8;
      *(undefined2 *)(iVar4 + 2) = 0;
    }
  }
  FUN_8028688c();
  return;
}

