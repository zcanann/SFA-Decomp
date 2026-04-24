// Function: FUN_80200450
// Entry: 80200450
// Size: 624 bytes

void FUN_80200450(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  float local_28 [10];
  
  uVar10 = FUN_80286838();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e6f44;
  iVar9 = *(int *)(*(int *)(iVar4 + 0xb8) + 0x40c);
  if ((*(char *)(iVar5 + 0x27b) == '\0') && (*(char *)(iVar9 + 0x34) == '\0')) {
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
    }
    else if ((iVar8 < 1) && (-1 < iVar8)) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
      else if ((*(int *)(iVar9 + 0x30) != 0) &&
              (uVar2 = FUN_80036d04(*(int *)(iVar5 + 0x2d0),*(int *)(iVar9 + 0x30)), uVar2 == 0)) {
        uVar3 = FUN_80036e58(*(undefined4 *)(iVar9 + 0x30),iVar4,(float *)0x0);
        *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
        if (*(int *)(iVar5 + 0x2d0) == 0) {
          *(undefined *)(iVar9 + 0x34) = 1;
        }
        *(float *)(iVar5 + 0x280) = FLOAT_803e6f40;
      }
    }
    if (((*(short *)(iVar9 + 0x1c) == -1) && (*(int *)(iVar9 + 0x3c) != 0)) &&
       (iVar4 = (**(code **)(**(int **)(*(int *)(iVar9 + 0x3c) + 0x68) + 0x20))(), iVar4 == 0)) {
      *(undefined4 *)(iVar9 + 0x3c) = 0;
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) & 0xfb;
    *(undefined *)(iVar9 + 0x34) = 0;
    uVar10 = extraout_f1;
    uVar2 = FUN_800138d4(*(short **)(iVar9 + 0x24));
    if (uVar2 == 0) {
      FUN_80013900(*(short **)(iVar9 + 0x24),iVar9 + 0x28);
    }
    else {
      if (*(int *)(iVar8 + 0x14) == -1) {
        FUN_8002cc9c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
        goto LAB_802006a8;
      }
      sVar1 = *(short *)(iVar8 + 0x24);
      iVar6 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
      iVar7 = iVar6 * 0xc;
      for (; iVar6 != 0; iVar6 = iVar6 + -1) {
        iVar7 = iVar7 + -0xc;
        FUN_80013978(*(short **)(iVar9 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar7));
      }
      *(undefined *)(iVar9 + 0x34) = 1;
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
      *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
    }
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      *(undefined4 *)(iVar5 + 0x2d0) = *(undefined4 *)(iVar9 + 0x30);
    }
    else if (((iVar8 < 1) && (-1 < iVar8)) && (*(int *)(iVar9 + 0x30) != 0)) {
      uVar3 = FUN_80036e58(*(int *)(iVar9 + 0x30),iVar4,local_28);
      *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
    }
    if (*(int *)(iVar5 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar4,iVar5,*(undefined4 *)(iVar9 + 0x28));
    }
  }
LAB_802006a8:
  FUN_80286884();
  return;
}

