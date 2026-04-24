// Function: FUN_802bb238
// Entry: 802bb238
// Size: 340 bytes

void FUN_802bb238(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  char cVar5;
  undefined4 uVar4;
  uint uVar6;
  undefined8 uVar7;
  undefined auStack56 [8];
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar7 = FUN_802860d4();
  uVar2 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar1 = (uint)((*(uint *)(param_3 + 0x314) & 2) != 0);
  if ((*(uint *)(param_3 + 0x314) & 4) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar6 = 0;
  for (; uVar1 != 0; uVar1 = (int)uVar1 >> 1) {
    if ((uVar1 & 1) != 0) {
      iVar3 = (int)uVar7 + (uVar6 & 0xff) * 0xc;
      local_2c = *(undefined4 *)(iVar3 + 0x9b0);
      local_28 = *(undefined4 *)(iVar3 + 0x9b4);
      local_24 = *(undefined4 *)(iVar3 + 0x9b8);
      local_30 = FLOAT_803e82a0;
      for (cVar5 = FUN_800221a0(2,6); cVar5 != '\0'; cVar5 = cVar5 + -1) {
        iVar3 = FUN_800221a0(0,1);
        (**(code **)(*DAT_803dca88 + 8))(uVar2,iVar3 + 0x1f9,auStack56,0x10001,0xffffffff,0);
      }
      uVar4 = FUN_8006ed24(*(undefined *)(param_3 + 0xbc),9);
      FUN_8000bb18(uVar2,uVar4);
      FUN_80014aa0((double)FLOAT_803e8244);
    }
    uVar6 = uVar6 + 1;
  }
  FUN_80286120();
  return;
}

