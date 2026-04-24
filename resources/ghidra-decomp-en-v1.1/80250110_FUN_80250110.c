// Function: FUN_80250110
// Entry: 80250110
// Size: 212 bytes

void FUN_80250110(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar3 = FUN_802501e4();
  if (param_1 != uVar3) {
    uVar3 = DAT_cc006c00;
    uVar4 = FUN_80250210();
    uVar5 = FUN_8025023c();
    FUN_80250220(0);
    FUN_802501f4(0);
    uVar1 = DAT_cc006c00;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xffffffbf;
    FUN_80243e74();
    FUN_80250520();
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 | uVar1 & 0x40;
    uVar1 = DAT_cc006c00;
    DAT_cc006c00 = uVar1 & 0xffffffdf | 0x20;
    uVar1 = DAT_cc006c00;
    DAT_cc006c00 = uVar1 & 0xfffffffd | param_1 << 1;
    FUN_80243e9c();
    FUN_8024ff34(uVar3 & 1);
    FUN_802501f4(uVar4);
    FUN_80250220(uVar5);
  }
  return;
}

