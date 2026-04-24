// Function: FUN_80255538
// Entry: 80255538
// Size: 2180 bytes

void FUN_80255538(void)

{
  undefined *puVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  local_50 = DAT_803e7658;
  local_54 = DAT_803e765c;
  local_58 = DAT_803e7660;
  iVar2 = FUN_8024d900();
  if (iVar2 == 2) {
    puVar1 = (undefined *)0x8032e698;
    goto LAB_802555dc;
  }
  if (iVar2 < 2) {
    if (iVar2 == 0) {
      puVar1 = &DAT_8032e620;
      goto LAB_802555dc;
    }
    if (-1 < iVar2) {
      puVar1 = (undefined *)0x8032e6d4;
      goto LAB_802555dc;
    }
  }
  else if (iVar2 == 5) {
    puVar1 = (undefined *)0x8032e710;
    goto LAB_802555dc;
  }
  puVar1 = &DAT_8032e620;
LAB_802555dc:
  local_5c = local_50;
  FUN_8025908c(&local_5c,0xffffff);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_80257f10(1,1,5,0x3c,0,0x7d);
  FUN_80257f10(2,1,6,0x3c,0,0x7d);
  FUN_80257f10(3,1,7,0x3c,0,0x7d);
  FUN_80257f10(4,1,8,0x3c,0,0x7d);
  FUN_80257f10(5,1,9,0x3c,0,0x7d);
  FUN_80257f10(6,1,10,0x3c,0,0x7d);
  FUN_80257f10(7,1,0xb,0x3c,0,0x7d);
  FUN_802581e0(1);
  FUN_802573f8();
  FUN_80257f00();
  uVar3 = 9;
  do {
    FUN_80257e74(uVar3,DAT_803dc5a8,0);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x19);
  FUN_80258a14(6,0);
  FUN_80258a6c(6,0);
  FUN_80258ac0(0,0,0);
  FUN_80258ac0(1,0,0);
  FUN_80258ac0(2,0,0);
  FUN_80258ac0(3,0,0);
  FUN_80258ac0(4,0,0);
  FUN_80258ac0(5,0,0);
  FUN_80258ac0(6,0,0);
  FUN_80258ac0(7,0,0);
  local_4c = FLOAT_803e7664;
  local_48 = FLOAT_803e7668;
  local_44 = FLOAT_803e7668;
  local_40 = FLOAT_803e7668;
  local_3c = FLOAT_803e7668;
  local_38 = FLOAT_803e7664;
  local_34 = FLOAT_803e7668;
  local_30 = FLOAT_803e7668;
  local_2c = FLOAT_803e7668;
  local_28 = FLOAT_803e7668;
  local_24 = FLOAT_803e7664;
  local_20 = FLOAT_803e7668;
  FUN_8025d0a8(&local_4c,0);
  FUN_8025d0e4(&local_4c,0);
  FUN_8025d124(0);
  FUN_8025d160(&local_4c,0x3c,0);
  FUN_8025d160(&local_4c,0x7d,0);
  uStack12 = (uint)*(ushort *)(puVar1 + 4);
  uStack20 = (uint)*(ushort *)(puVar1 + 8);
  dVar4 = (double)FLOAT_803e7668;
  local_10 = 0x43300000;
  local_18 = 0x43300000;
  FUN_8025d300(dVar4,dVar4,(double)(float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e7670),
               (double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7670),dVar4,
               (double)FLOAT_803e7664);
  FUN_80258b74(0);
  FUN_80258b24(2);
  FUN_8025d468(0);
  FUN_8025d324(0,0,*(undefined2 *)(puVar1 + 4),*(undefined2 *)(puVar1 + 6));
  FUN_8025d424(0,0);
  FUN_80259e58(0);
  FUN_80259ea4(4,0,0,1,0,0,2);
  local_60 = local_54;
  FUN_80259b88(4,&local_60);
  local_64 = local_58;
  FUN_80259cf0(4,&local_64);
  FUN_80259ea4(5,0,0,1,0,0,2);
  local_68 = local_54;
  FUN_80259b88(5,&local_68);
  local_6c = local_58;
  FUN_80259cf0(5,&local_6c);
  FUN_8025aaac();
  uVar3 = 0;
  *(undefined4 *)(DAT_803dc5a8 + 0x2c8) = 0;
  *(undefined4 *)(DAT_803dc5a8 + 0x2cc) = 0;
  FUN_8025aaf4(&LAB_80254ccc);
  FUN_8025ab08(&LAB_80254d48);
  FUN_8025c0c4(0,0,0,4);
  FUN_8025c0c4(1,1,1,4);
  FUN_8025c0c4(2,2,2,4);
  FUN_8025c0c4(3,3,3,4);
  FUN_8025c0c4(4,4,4,4);
  FUN_8025c0c4(5,5,5,4);
  FUN_8025c0c4(6,6,6,4);
  FUN_8025c0c4(7,7,7,4);
  FUN_8025c0c4(8,0xff,0xff,0xff);
  FUN_8025c0c4(9,0xff,0xff,0xff);
  FUN_8025c0c4(10,0xff,0xff,0xff);
  FUN_8025c0c4(0xb,0xff,0xff,0xff);
  FUN_8025c0c4(0xc,0xff,0xff,0xff);
  FUN_8025c0c4(0xd,0xff,0xff,0xff);
  FUN_8025c0c4(0xe,0xff,0xff,0xff);
  FUN_8025c0c4(0xf,0xff,0xff,0xff);
  FUN_8025c2a0(1);
  FUN_8025b89c(0,3);
  FUN_8025bff0(7,0,0,7,0);
  FUN_8025c040(0,0x11,0);
  do {
    FUN_8025be20(uVar3,6);
    FUN_8025be8c(uVar3,0);
    FUN_8025bef8(uVar3,0,0);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x10);
  FUN_8025bf50(0,0,1,2,3);
  FUN_8025bf50(1,0,0,0,3);
  FUN_8025bf50(2,1,1,1,3);
  FUN_8025bf50(3,2,2,2,3);
  uVar3 = 0;
  do {
    FUN_8025b71c(uVar3);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x10);
  FUN_8025b6f0(0);
  FUN_8025b3e4(0,0,0);
  FUN_8025b3e4(1,0,0);
  FUN_8025b3e4(2,0,0);
  FUN_8025b3e4(3,0,0);
  local_70 = local_54;
  FUN_8025c2d4((double)FLOAT_803e7668,(double)FLOAT_803e7664,(double)FLOAT_803e766c,
               (double)FLOAT_803e7664,0,&local_70);
  FUN_8025c484(0,0,0);
  FUN_8025c584(0,4,5,0);
  FUN_8025c688(1);
  FUN_8025c6c8(1);
  FUN_8025c708(1,3,1);
  FUN_8025c780(1);
  FUN_8025c8d0(1);
  FUN_8025c910(0,0);
  FUN_8025c7c0(0,0);
  FUN_8025c964(1,1);
  FUN_8025c99c(puVar1[0x18],(uint)*(ushort *)(puVar1 + 0x10) == (uint)*(ushort *)(puVar1 + 8) << 1);
  FUN_80258bdc(0,0,*(undefined2 *)(puVar1 + 4),*(undefined2 *)(puVar1 + 6));
  FUN_80258d5c(*(undefined2 *)(puVar1 + 4),*(undefined2 *)(puVar1 + 6));
  uStack20 = (uint)*(ushort *)(puVar1 + 8);
  uStack12 = (uint)*(ushort *)(puVar1 + 6);
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  FUN_80258fb8((double)((float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7670) /
                       (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e7670)));
  FUN_80258f3c(3);
  FUN_802590f4(puVar1[0x19],puVar1 + 0x1a,1,puVar1 + 0x32);
  FUN_8025931c(0);
  FUN_80258f10(0);
  FUN_80259638();
  FUN_802585d4(1);
  FUN_80258530(1);
  FUN_80258604(0);
  FUN_8025854c(0,0,1,0xf);
  FUN_80258508(7,0);
  FUN_8025851c(1);
  FUN_802585f0(0,0);
  FUN_80258620(1,7,1);
  FUN_8025d514(0x23,0x16);
  FUN_8025ddac();
  return;
}

