// Function: FUN_800d93e8
// Entry: 800d93e8
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x800d953c) */
/* WARNING: Removing unreachable block (ram,0x800d93f8) */

void FUN_800d93e8(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286838();
  iVar5 = (int)uVar8;
  bVar3 = false;
  iVar6 = 0;
  uVar7 = extraout_f1;
  if (*(short *)(iVar5 + 0x270) != *(short *)(iVar5 + 0x272)) {
    *(undefined *)(iVar5 + 0x27b) = 1;
    *(undefined2 *)(iVar5 + 0x32e) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(iVar5 + 0x270);
    iVar4 = (**(code **)(param_3 + sVar1 * 4))(uVar7,(int)((ulonglong)uVar8 >> 0x20),iVar5);
    if (iVar4 < 1) {
      if (iVar4 < 0) {
        if (-iVar4 == (int)sVar1) {
          *(undefined *)(iVar5 + 0x27b) = 0;
        }
        else {
          *(short *)(iVar5 + 0x272) = sVar1;
          *(undefined *)(iVar5 + 0x27b) = 1;
          *(undefined2 *)(iVar5 + 0x32e) = 0;
        }
        *(short *)(iVar5 + 0x270) = (short)-iVar4;
        bVar2 = true;
        bVar3 = true;
      }
      else {
        bVar2 = true;
      }
    }
    else {
      *(undefined2 *)(iVar5 + 0x272) = *(undefined2 *)(iVar5 + 0x270);
      *(short *)(iVar5 + 0x270) = (short)iVar4 + -1;
      *(undefined *)(iVar5 + 0x27b) = 1;
      *(undefined2 *)(iVar5 + 0x32e) = 0;
    }
    iVar6 = iVar6 + 1;
    if (0xff < iVar6) {
      bVar2 = true;
    }
  } while (!bVar2);
  *(undefined2 *)(iVar5 + 0x272) = *(undefined2 *)(iVar5 + 0x270);
  if ((!bVar3) &&
     (*(undefined *)(iVar5 + 0x27b) = 0,
     FLOAT_803e123c <
     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x338) ^ 0x80000000) -
            DOUBLE_803e1218))) {
    *(undefined *)(iVar5 + 0x27b) = 0;
  }
  FUN_80286884();
  return;
}

