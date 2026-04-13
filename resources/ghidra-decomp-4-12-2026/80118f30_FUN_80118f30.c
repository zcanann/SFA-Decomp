// Function: FUN_80118f30
// Entry: 80118f30
// Size: 548 bytes

void FUN_80118f30(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  uint uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_8028682c();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  if ((DAT_803a6a58 != 0) && (DAT_803a6a5c == '\0')) {
    if (DAT_803a6a68 == 0) {
      DAT_803a6abc = iVar2 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ac4 = DAT_803a6abc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6acc = DAT_803a6ac4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ad4 = DAT_803a6acc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6adc = DAT_803a6ad4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ae4 = DAT_803a6adc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6aec = DAT_803a6ae4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6af4 = DAT_803a6aec + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6afc = DAT_803a6af4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      uVar6 = DAT_803a6afc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ab4 = iVar2;
    }
    else {
      uVar6 = iVar2 + DAT_803a6a18;
      DAT_803a6a6c = iVar2;
    }
    puVar5 = &DAT_803a69c0;
    uVar3 = DAT_803a6a40 * DAT_803a6a44;
    uVar1 = (uVar3 >> 2) + 0x1f & 0xffffffe0;
    uVar4 = 0;
    do {
      *(int *)(puVar5 + 0x144) = (int)uVar7;
      FUN_802420b0(uVar6,uVar3 + 0x1f & 0xffffffe0);
      *(undefined4 *)(puVar5 + 0x148) = param_3;
      FUN_802420b0(uVar6,uVar1);
      *(undefined4 *)(puVar5 + 0x14c) = param_4;
      FUN_802420b0(uVar6,uVar1);
      uVar6 = uVar6 + uVar1;
      puVar5 = puVar5 + 0x10;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 3);
    DAT_803a6a54 = param_6;
    if (DAT_803a6a5f != '\0') {
      DAT_803a6b3c = 0;
      uVar6 = DAT_803a6a08 * 4 + 0x1fU & 0xffffffe0;
      DAT_803a6b44 = param_5 + uVar6;
      DAT_803a6b4c = 0;
      DAT_803a6b54 = DAT_803a6b44 + uVar6;
      DAT_803a6b5c = 0;
      DAT_803a6b34 = param_5;
      DAT_803a6b38 = param_5;
      DAT_803a6b48 = DAT_803a6b44;
      DAT_803a6b58 = DAT_803a6b54;
    }
  }
  FUN_80286878();
  return;
}

