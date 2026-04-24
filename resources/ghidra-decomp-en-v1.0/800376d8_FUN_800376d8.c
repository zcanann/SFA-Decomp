// Function: FUN_800376d8
// Entry: 800376d8
// Size: 492 bytes

void FUN_800376d8(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  ulonglong uVar6;
  int local_28;
  int local_24 [9];
  
  uVar6 = FUN_802860d4();
  iVar1 = (int)(uVar6 >> 0x20);
  iVar2 = FUN_8002e0fc(local_24,&local_28);
  if ((uVar6 & 4) == 0) {
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      uVar5 = *(uint *)(iVar2 + local_24[0] * 4);
      if ((((uVar5 != param_3) || ((uVar6 & 1) == 0)) &&
          (((uVar6 & 2) != 0 || (iVar1 == *(short *)(uVar5 + 0x44))))) &&
         ((uVar5 != 0 && (puVar4 = *(uint **)(uVar5 + 0xdc), puVar4 != (uint *)0x0)))) {
        uVar3 = *puVar4;
        if (uVar3 < puVar4[1]) {
          puVar4[uVar3 * 3 + 2] = param_4;
          puVar4[uVar3 * 3 + 3] = param_3;
          puVar4[uVar3 * 3 + 4] = param_5;
          *puVar4 = *puVar4 + 1;
        }
        else {
          FUN_801378a8(s_objmsg___x___overflow_in_object___802cae48,param_4,
                       (int)*(short *)(uVar5 + 0x44),(int)*(short *)(uVar5 + 0x46),
                       (int)*(short *)(param_3 + 0x46));
        }
      }
    }
  }
  else {
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      uVar5 = *(uint *)(iVar2 + local_24[0] * 4);
      if ((((uVar5 != param_3) || ((uVar6 & 1) == 0)) &&
          (((uVar6 & 2) != 0 || (iVar1 == *(short *)(uVar5 + 0x46))))) &&
         ((uVar5 != 0 && (puVar4 = *(uint **)(uVar5 + 0xdc), puVar4 != (uint *)0x0)))) {
        uVar3 = *puVar4;
        if (uVar3 < puVar4[1]) {
          puVar4[uVar3 * 3 + 2] = param_4;
          puVar4[uVar3 * 3 + 3] = param_3;
          puVar4[uVar3 * 3 + 4] = param_5;
          *puVar4 = *puVar4 + 1;
        }
        else {
          FUN_801378a8(s_objmsg___x___overflow_in_object___802cae48,param_4,
                       (int)*(short *)(uVar5 + 0x44),(int)*(short *)(uVar5 + 0x46),
                       (int)*(short *)(param_3 + 0x46));
        }
      }
    }
  }
  FUN_80286120();
  return;
}

