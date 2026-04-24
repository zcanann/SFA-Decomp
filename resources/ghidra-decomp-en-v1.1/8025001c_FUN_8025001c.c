// Function: FUN_8025001c
// Entry: 8025001c
// Size: 224 bytes

void FUN_8025001c(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar2 = FUN_802500fc();
  if ((param_1 != uVar2) && (uVar2 = DAT_cc006c00, DAT_cc006c00 = uVar2 & 0xffffffbf, param_1 == 0))
  {
    uVar3 = FUN_80250210();
    uVar4 = FUN_8025023c();
    uVar2 = DAT_cc006c00;
    uVar5 = FUN_802501e4();
    FUN_802501f4(0);
    FUN_80250220(0);
    FUN_80243e74();
    FUN_80250520();
    uVar1 = DAT_cc006c00;
    DAT_cc006c00 = uVar1 & 0xffffffdf | 0x20;
    uVar1 = DAT_cc006c00;
    DAT_cc006c00 = uVar1 & 0xfffffffd | uVar5 << 1;
    uVar1 = DAT_cc006c00;
    DAT_cc006c00 = uVar1 & 0xfffffffe | uVar2 & 1;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 | 0x40;
    FUN_80243e9c();
    FUN_802501f4(uVar3);
    FUN_80250220(uVar4);
  }
  return;
}

