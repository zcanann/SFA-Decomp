// Function: FUN_800d915c
// Entry: 800d915c
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x800d92b0) */

void FUN_800d915c(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar9 = FUN_802860d4();
  iVar5 = (int)uVar9;
  bVar3 = false;
  iVar6 = 0;
  uVar8 = extraout_f1;
  if (*(short *)(iVar5 + 0x270) != *(short *)(iVar5 + 0x272)) {
    *(undefined *)(iVar5 + 0x27b) = 1;
    *(undefined2 *)(iVar5 + 0x32e) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(iVar5 + 0x270);
    iVar4 = (**(code **)(param_3 + sVar1 * 4))(uVar8,(int)((ulonglong)uVar9 >> 0x20),iVar5);
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
     FLOAT_803e05bc <
     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x338) ^ 0x80000000) -
            DOUBLE_803e0598))) {
    *(undefined *)(iVar5 + 0x27b) = 0;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286120();
  return;
}

