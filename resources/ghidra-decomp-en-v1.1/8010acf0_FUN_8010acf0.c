// Function: FUN_8010acf0
// Entry: 8010acf0
// Size: 500 bytes

void FUN_8010acf0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  puVar4 = (undefined4 *)uVar10;
  *puVar4 = 0xffffffff;
  puVar4[1] = 0xffffffff;
  puVar4[2] = 0xffffffff;
  puVar4[3] = 0xffffffff;
  if (iVar2 != 0) {
    puVar4[1] = *(undefined4 *)(iVar2 + 0x14);
    iVar7 = 0;
    uVar6 = param_11;
    uVar9 = extraout_f1;
    do {
      iVar8 = (int)((ulonglong)uVar10 >> 0x20);
      uVar5 = (uint)uVar10;
      if (((-1 < *(int *)(iVar8 + 0x1c)) &&
          (uVar10 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar3 = (int)((ulonglong)uVar10 >> 0x20),
          uVar5 = (uint)uVar10, uVar9 = extraout_f1_00, iVar3 != 0)) &&
         ((*(byte *)(iVar3 + 0x31) == param_11 ||
          ((*(byte *)(iVar3 + 0x32) == param_11 || (*(byte *)(iVar3 + 0x33) == param_11)))))) {
        bVar1 = ((int)*(char *)(iVar2 + 0x1b) & 1 << iVar7) == 0;
        if (bVar1) {
          if (bVar1) {
            puVar4[2] = *(undefined4 *)(iVar8 + 0x1c);
          }
        }
        else {
          *puVar4 = *(undefined4 *)(iVar8 + 0x1c);
        }
      }
      uVar10 = CONCAT44(iVar8 + 4,uVar5);
      iVar7 = iVar7 + 1;
    } while (iVar7 < 5);
    if (((-1 < (int)puVar4[2]) &&
        (uVar10 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar2 = (int)((ulonglong)uVar10 >> 0x20),
        uVar5 = (uint)uVar10, uVar9 = extraout_f1_01, iVar2 != 0)) &&
       ((*(byte *)(iVar2 + 0x31) == param_11 ||
        ((*(byte *)(iVar2 + 0x32) == param_11 || (*(byte *)(iVar2 + 0x33) == param_11)))))) {
      iVar7 = 0;
      do {
        iVar8 = (int)((ulonglong)uVar10 >> 0x20);
        uVar5 = (uint)uVar10;
        if ((((-1 < *(int *)(iVar8 + 0x1c)) &&
             (uVar5 = (uint)*(char *)(iVar2 + 0x1b), (uVar5 & 1 << iVar7) == 0)) &&
            (uVar10 = (**(code **)(*DAT_803dd71c + 0x1c))(),
            iVar3 = (int)((ulonglong)uVar10 >> 0x20), uVar5 = (uint)uVar10, uVar9 = extraout_f1_02,
            iVar3 != 0)) &&
           (((*(byte *)(iVar3 + 0x31) == param_11 || (*(byte *)(iVar3 + 0x32) == param_11)) ||
            (*(byte *)(iVar3 + 0x33) == param_11)))) {
          puVar4[3] = *(undefined4 *)(iVar8 + 0x1c);
        }
        uVar10 = CONCAT44(iVar8 + 4,uVar5);
        iVar7 = iVar7 + 1;
      } while (iVar7 < 5);
    }
    if (((int)puVar4[1] < 0) || ((int)puVar4[2] < 0)) {
      FUN_80137c30(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_PATHCAM_error__need_at_least_two_8031a904,uVar5,uVar6,param_12,param_13,
                   param_14,param_15,param_16);
    }
  }
  FUN_8028688c();
  return;
}

