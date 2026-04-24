// Function: FUN_8003759c
// Entry: 8003759c
// Size: 316 bytes

void FUN_8003759c(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)

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
  
  uVar7 = FUN_802860d0();
  dVar6 = extraout_f1;
  iVar1 = FUN_8002e0fc(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    uVar4 = *(uint *)(iVar1 + local_34[0] * 4);
    if ((((uVar4 != param_3) || ((uVar7 & 1) == 0)) &&
        ((*(short *)(uVar4 + 0x46) == (short)(uVar7 >> 0x20) || ((uVar7 & 2) != 0)))) &&
       (((dVar5 = (double)FUN_80021704(param_3 + 0x18,uVar4 + 0x18), dVar5 < dVar6 && (uVar4 != 0))
        && (puVar3 = *(uint **)(uVar4 + 0xdc), puVar3 != (uint *)0x0)))) {
      uVar2 = *puVar3;
      if (uVar2 < puVar3[1]) {
        puVar3[uVar2 * 3 + 2] = param_4;
        puVar3[uVar2 * 3 + 3] = param_3;
        puVar3[uVar2 * 3 + 4] = param_5;
        *puVar3 = *puVar3 + 1;
      }
      else {
        FUN_801378a8(s_objmsg___x___overflow_in_object___802cae48,param_4,
                     (int)*(short *)(uVar4 + 0x44),(int)*(short *)(uVar4 + 0x46),
                     (int)*(short *)(param_3 + 0x46));
      }
    }
  }
  FUN_8028611c();
  return;
}

