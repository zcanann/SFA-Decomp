// Function: FUN_80037694
// Entry: 80037694
// Size: 316 bytes

void FUN_80037694(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  double extraout_f1;
  double dVar5;
  double dVar6;
  uint6 uVar7;
  int local_38;
  int local_34 [13];
  
  uVar7 = FUN_80286834();
  dVar6 = extraout_f1;
  iVar1 = FUN_8002e1f4(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    uVar4 = *(uint *)(iVar1 + local_34[0] * 4);
    if ((((uVar4 != param_11) || ((uVar7 & 1) == 0)) &&
        ((*(short *)(uVar4 + 0x46) == (short)(uVar7 >> 0x20) || ((uVar7 & 2) != 0)))) &&
       (((dVar5 = (double)FUN_800217c8((float *)(param_11 + 0x18),(float *)(uVar4 + 0x18)),
         dVar5 < dVar6 && (uVar4 != 0)) &&
        (puVar3 = *(uint **)(uVar4 + 0xdc), puVar3 != (uint *)0x0)))) {
      uVar2 = *puVar3;
      if (uVar2 < puVar3[1]) {
        puVar3[uVar2 * 3 + 2] = param_12;
        puVar3[uVar2 * 3 + 3] = param_11;
        puVar3[uVar2 * 3 + 4] = param_13;
        *puVar3 = *puVar3 + 1;
      }
      else {
        FUN_80137c30(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_objmsg___x___overflow_in_object___802cba20,param_12,
                     (int)*(short *)(uVar4 + 0x44),(int)*(short *)(uVar4 + 0x46),
                     (int)*(short *)(param_11 + 0x46),param_14,param_15,param_16);
      }
    }
  }
  FUN_80286880();
  return;
}

