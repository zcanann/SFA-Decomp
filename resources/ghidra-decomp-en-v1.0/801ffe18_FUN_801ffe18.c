// Function: FUN_801ffe18
// Entry: 801ffe18
// Size: 624 bytes

void FUN_801ffe18(void)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  float local_28 [10];
  
  uVar9 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar7 = *(int *)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e62ac;
  iVar8 = *(int *)(*(int *)(iVar4 + 0xb8) + 0x40c);
  if ((*(char *)(iVar5 + 0x27b) == '\0') && (*(char *)(iVar8 + 0x34) == '\0')) {
    iVar7 = *(int *)(iVar8 + 0x2c);
    if (iVar7 == 1) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar8 + 0x34) = 1;
      }
    }
    else if ((iVar7 < 1) && (-1 < iVar7)) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar8 + 0x34) = 1;
      }
      else if ((*(int *)(iVar8 + 0x30) != 0) && (iVar7 = FUN_80036c0c(), iVar7 == 0)) {
        uVar3 = FUN_80036d60(*(undefined4 *)(iVar8 + 0x30),iVar4,0);
        *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
        if (*(int *)(iVar5 + 0x2d0) == 0) {
          *(undefined *)(iVar8 + 0x34) = 1;
        }
        *(float *)(iVar5 + 0x280) = FLOAT_803e62a8;
      }
    }
    if (((*(short *)(iVar8 + 0x1c) == -1) && (*(int *)(iVar8 + 0x3c) != 0)) &&
       (iVar4 = (**(code **)(**(int **)(*(int *)(iVar8 + 0x3c) + 0x68) + 0x20))(), iVar4 == 0)) {
      *(undefined4 *)(iVar8 + 0x3c) = 0;
      *(undefined *)(iVar8 + 0x34) = 1;
    }
  }
  else {
    *(byte *)(iVar8 + 0x15) = *(byte *)(iVar8 + 0x15) & 0xfb;
    *(undefined *)(iVar8 + 0x34) = 0;
    iVar2 = FUN_800138b4(*(undefined4 *)(iVar8 + 0x24));
    if (iVar2 == 0) {
      FUN_800138e0(*(undefined4 *)(iVar8 + 0x24),iVar8 + 0x28);
    }
    else {
      if (*(int *)(iVar7 + 0x14) == -1) {
        FUN_8002cbc4(iVar4);
        goto LAB_80200070;
      }
      sVar1 = *(short *)(iVar7 + 0x24);
      iVar2 = (int)*(short *)(&DAT_80329518 + sVar1 * 8);
      iVar6 = iVar2 * 0xc;
      for (; iVar2 != 0; iVar2 = iVar2 + -1) {
        iVar6 = iVar6 + -0xc;
        FUN_80013958(*(undefined4 *)(iVar8 + 0x24),(&PTR_DAT_80329514)[sVar1 * 2] + iVar6);
      }
      *(undefined *)(iVar8 + 0x34) = 1;
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
    }
    iVar7 = *(int *)(iVar8 + 0x2c);
    if (iVar7 == 1) {
      *(undefined4 *)(iVar5 + 0x2d0) = *(undefined4 *)(iVar8 + 0x30);
    }
    else if (((iVar7 < 1) && (-1 < iVar7)) && (*(int *)(iVar8 + 0x30) != 0)) {
      uVar3 = FUN_80036d60(*(int *)(iVar8 + 0x30),iVar4,local_28);
      *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
    }
    if (*(int *)(iVar5 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dca8c + 0x14))(iVar4,iVar5,*(undefined4 *)(iVar8 + 0x28));
    }
  }
LAB_80200070:
  FUN_80286120(0);
  return;
}

