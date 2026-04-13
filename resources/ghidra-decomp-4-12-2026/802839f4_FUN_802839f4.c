// Function: FUN_802839f4
// Entry: 802839f4
// Size: 428 bytes

void FUN_802839f4(int param_1,undefined2 param_2,undefined4 *param_3,int param_4,undefined4 param_5,
                 undefined4 param_6,int param_7,char param_8)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  byte bVar7;
  uint *puVar8;
  
  bVar1 = DAT_803deff0;
  iVar5 = 0;
  iVar2 = param_1 * 0xf4;
  uVar6 = 0;
  for (bVar7 = 0; bVar7 <= bVar1; bVar7 = bVar7 + 1) {
    puVar8 = (uint *)(iVar2 + DAT_803defc4 + iVar5 + 0x24);
    uVar4 = *puVar8;
    iVar5 = iVar5 + 4;
    *puVar8 = 0;
    uVar6 = uVar6 | uVar4 & 0x20;
  }
  *(uint *)(DAT_803defc4 + iVar2 + 0x24) = uVar6;
  *(undefined4 *)(DAT_803defc4 + iVar2 + 0x1c) = param_5;
  *(undefined4 *)(DAT_803defc4 + iVar2 + 0x18) = param_6;
  *(undefined4 *)(DAT_803defc4 + iVar2 + 0xf0) = 0;
  *(undefined2 *)(DAT_803defc4 + iVar2 + 0x70) = param_2;
  uVar3 = param_3[1];
  iVar5 = DAT_803defc4 + iVar2;
  *(undefined4 *)(iVar5 + 0x74) = *param_3;
  *(undefined4 *)(iVar5 + 0x78) = uVar3;
  uVar3 = param_3[3];
  *(undefined4 *)(iVar5 + 0x7c) = param_3[2];
  *(undefined4 *)(iVar5 + 0x80) = uVar3;
  uVar3 = param_3[5];
  *(undefined4 *)(iVar5 + 0x84) = param_3[4];
  *(undefined4 *)(iVar5 + 0x88) = uVar3;
  uVar3 = param_3[7];
  *(undefined4 *)(iVar5 + 0x8c) = param_3[6];
  *(undefined4 *)(iVar5 + 0x90) = uVar3;
  if (param_4 != 0) {
    *(undefined *)(DAT_803defc4 + iVar2 + 0xa4) = 0;
    *(undefined4 *)(DAT_803defc4 + iVar2 + 0xb8) = 0;
    *(undefined4 *)(DAT_803defc4 + iVar2 + 0xbc) = 0;
    *(undefined2 *)(DAT_803defc4 + iVar2 + 0xc0) = 0x7fff;
    *(undefined4 *)(DAT_803defc4 + iVar2 + 0xc4) = 0;
  }
  *(undefined *)(DAT_803defc4 + iVar2 + 0xe4) = 0xff;
  *(undefined *)(DAT_803defc4 + iVar2 + 0xe5) = 0xff;
  *(undefined *)(DAT_803defc4 + iVar2 + 0xe6) = 0xff;
  *(undefined *)(DAT_803defc4 + iVar2 + 0xe7) = 0xff;
  if (param_7 != 0) {
    FUN_80283eec(param_1,0);
    FUN_80283f18(param_1,1);
  }
  FUN_80283f44(param_1,param_8);
  return;
}

