// Function: FUN_80118c88
// Entry: 80118c88
// Size: 548 bytes

void FUN_80118c88(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined *puVar6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860c8();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  if ((DAT_803a5df8 == 0) || (DAT_803a5dfc != '\0')) {
    uVar4 = 0;
  }
  else {
    if (DAT_803a5e08 == 0) {
      DAT_803a5e5c = iVar2 + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e64 = DAT_803a5e5c + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e6c = DAT_803a5e64 + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e74 = DAT_803a5e6c + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e7c = DAT_803a5e74 + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e84 = DAT_803a5e7c + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e8c = DAT_803a5e84 + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e94 = DAT_803a5e8c + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e9c = DAT_803a5e94 + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      iVar7 = DAT_803a5e9c + (DAT_803a5da4 + 0x1fU & 0xffffffe0);
      DAT_803a5e54 = iVar2;
    }
    else {
      iVar7 = iVar2 + DAT_803a5db8;
      DAT_803a5e0c = iVar2;
    }
    puVar6 = &DAT_803a5d60;
    uVar3 = DAT_803a5de0 * DAT_803a5de4;
    uVar1 = (uVar3 >> 2) + 0x1f & 0xffffffe0;
    uVar5 = 0;
    do {
      *(int *)(puVar6 + 0x144) = (int)uVar8;
      FUN_802419b8(iVar7,uVar3 + 0x1f & 0xffffffe0);
      *(undefined4 *)(puVar6 + 0x148) = param_3;
      FUN_802419b8(iVar7,uVar1);
      *(undefined4 *)(puVar6 + 0x14c) = param_4;
      FUN_802419b8(iVar7,uVar1);
      iVar7 = iVar7 + uVar1;
      puVar6 = puVar6 + 0x10;
      uVar5 = uVar5 + 1;
    } while (uVar5 < 3);
    if (DAT_803a5dff != '\0') {
      DAT_803a5edc = 0;
      uVar1 = DAT_803a5da8 * 4 + 0x1fU & 0xffffffe0;
      DAT_803a5ee4 = param_5 + uVar1;
      DAT_803a5eec = 0;
      DAT_803a5ef4 = DAT_803a5ee4 + uVar1;
      DAT_803a5efc = 0;
      DAT_803a5ed4 = param_5;
      DAT_803a5ed8 = param_5;
      DAT_803a5ee8 = DAT_803a5ee4;
      DAT_803a5ef8 = DAT_803a5ef4;
    }
    uVar4 = 1;
    DAT_803a5df4 = param_6;
  }
  FUN_80286114(uVar4);
  return;
}

