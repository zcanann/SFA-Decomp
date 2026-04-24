// Function: FUN_800377d0
// Entry: 800377d0
// Size: 492 bytes

void FUN_800377d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  ulonglong uVar7;
  int local_28;
  int local_24 [9];
  
  uVar7 = FUN_80286838();
  iVar1 = (int)(uVar7 >> 0x20);
  uVar6 = extraout_f1;
  iVar2 = FUN_8002e1f4(local_24,&local_28);
  if ((uVar7 & 4) == 0) {
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      uVar5 = *(uint *)(iVar2 + local_24[0] * 4);
      if ((((uVar5 != param_11) || ((uVar7 & 1) == 0)) &&
          (((uVar7 & 2) != 0 || (iVar1 == *(short *)(uVar5 + 0x44))))) &&
         ((uVar5 != 0 && (puVar4 = *(uint **)(uVar5 + 0xdc), puVar4 != (uint *)0x0)))) {
        uVar3 = *puVar4;
        if (uVar3 < puVar4[1]) {
          puVar4[uVar3 * 3 + 2] = param_12;
          puVar4[uVar3 * 3 + 3] = param_11;
          puVar4[uVar3 * 3 + 4] = param_13;
          *puVar4 = *puVar4 + 1;
        }
        else {
          uVar6 = FUN_80137c30(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               s_objmsg___x___overflow_in_object___802cba20,param_12,
                               (int)*(short *)(uVar5 + 0x44),(int)*(short *)(uVar5 + 0x46),
                               (int)*(short *)(param_11 + 0x46),param_14,param_15,param_16);
        }
      }
    }
  }
  else {
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      uVar5 = *(uint *)(iVar2 + local_24[0] * 4);
      if ((((uVar5 != param_11) || ((uVar7 & 1) == 0)) &&
          (((uVar7 & 2) != 0 || (iVar1 == *(short *)(uVar5 + 0x46))))) &&
         ((uVar5 != 0 && (puVar4 = *(uint **)(uVar5 + 0xdc), puVar4 != (uint *)0x0)))) {
        uVar3 = *puVar4;
        if (uVar3 < puVar4[1]) {
          puVar4[uVar3 * 3 + 2] = param_12;
          puVar4[uVar3 * 3 + 3] = param_11;
          puVar4[uVar3 * 3 + 4] = param_13;
          *puVar4 = *puVar4 + 1;
        }
        else {
          uVar6 = FUN_80137c30(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               s_objmsg___x___overflow_in_object___802cba20,param_12,
                               (int)*(short *)(uVar5 + 0x44),(int)*(short *)(uVar5 + 0x46),
                               (int)*(short *)(param_11 + 0x46),param_14,param_15,param_16);
        }
      }
    }
  }
  FUN_80286884();
  return;
}

