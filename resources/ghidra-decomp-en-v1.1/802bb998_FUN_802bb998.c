// Function: FUN_802bb998
// Entry: 802bb998
// Size: 340 bytes

void FUN_802bb998(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  ushort uVar6;
  uint uVar7;
  undefined8 uVar8;
  undefined auStack_38 [8];
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar8 = FUN_80286838();
  uVar2 = (uint)((ulonglong)uVar8 >> 0x20);
  uVar1 = (uint)((*(uint *)(param_3 + 0x314) & 2) != 0);
  if ((*(uint *)(param_3 + 0x314) & 4) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar7 = 0;
  for (; uVar1 != 0; uVar1 = (int)uVar1 >> 1) {
    if ((uVar1 & 1) != 0) {
      iVar3 = (int)uVar8 + (uVar7 & 0xff) * 0xc;
      local_2c = *(undefined4 *)(iVar3 + 0x9b0);
      local_28 = *(undefined4 *)(iVar3 + 0x9b4);
      local_24 = *(undefined4 *)(iVar3 + 0x9b8);
      local_30 = FLOAT_803e8f38;
      uVar4 = FUN_80022264(2,6);
      for (uVar4 = uVar4 & 0xff; (uVar4 & 0xff) != 0; uVar4 = uVar4 - 1) {
        uVar5 = FUN_80022264(0,1);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,uVar5 + 0x1f9,auStack_38,0x10001,0xffffffff,0);
      }
      uVar6 = FUN_8006eea0((uint)*(byte *)(param_3 + 0xbc),9);
      FUN_8000bb38(uVar2,uVar6);
      FUN_80014acc((double)FLOAT_803e8edc);
    }
    uVar7 = uVar7 + 1;
  }
  FUN_80286884();
  return;
}

