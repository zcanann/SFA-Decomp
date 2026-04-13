// Function: FUN_80255c9c
// Entry: 80255c9c
// Size: 2180 bytes

void FUN_80255c9c(void)

{
  undefined *puVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  uint local_70;
  uint local_6c;
  uint local_68;
  uint local_64;
  uint local_60;
  undefined4 local_5c;
  uint local_58;
  uint local_54;
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
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  local_50 = DAT_803e82f0;
  local_54 = DAT_803e82f4;
  local_58 = DAT_803e82f8;
  iVar2 = FUN_8024e064();
  if (iVar2 == 2) {
    puVar1 = (undefined *)0x8032f2f0;
    goto LAB_80255d40;
  }
  if (iVar2 < 2) {
    if (iVar2 == 0) {
      puVar1 = &DAT_8032f278;
      goto LAB_80255d40;
    }
    if (-1 < iVar2) {
      puVar1 = (undefined *)0x8032f32c;
      goto LAB_80255d40;
    }
  }
  else if (iVar2 == 5) {
    puVar1 = (undefined *)0x8032f368;
    goto LAB_80255d40;
  }
  puVar1 = &DAT_8032f278;
LAB_80255d40:
  local_5c = local_50;
  FUN_802597f0((undefined *)&local_5c,0xffffff);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80258674(1,1,5,0x3c,0,0x7d);
  FUN_80258674(2,1,6,0x3c,0,0x7d);
  FUN_80258674(3,1,7,0x3c,0,0x7d);
  FUN_80258674(4,1,8,0x3c,0,0x7d);
  FUN_80258674(5,1,9,0x3c,0,0x7d);
  FUN_80258674(6,1,10,0x3c,0,0x7d);
  FUN_80258674(7,1,0xb,0x3c,0,0x7d);
  FUN_80258944(1);
  FUN_80257b5c();
  FUN_80258664();
  uVar3 = 9;
  do {
    FUN_802585d8(uVar3,DAT_803dd210,0);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x19);
  FUN_80259178(6,0);
  FUN_802591d0(6,0);
  FUN_80259224(0,0,0);
  FUN_80259224(1,0,0);
  FUN_80259224(2,0,0);
  FUN_80259224(3,0,0);
  FUN_80259224(4,0,0);
  FUN_80259224(5,0,0);
  FUN_80259224(6,0,0);
  FUN_80259224(7,0,0);
  local_4c = FLOAT_803e82fc;
  local_48 = FLOAT_803e8300;
  local_44 = FLOAT_803e8300;
  local_40 = FLOAT_803e8300;
  local_3c = FLOAT_803e8300;
  local_38 = FLOAT_803e82fc;
  local_34 = FLOAT_803e8300;
  local_30 = FLOAT_803e8300;
  local_2c = FLOAT_803e8300;
  local_28 = FLOAT_803e8300;
  local_24 = FLOAT_803e82fc;
  local_20 = FLOAT_803e8300;
  FUN_8025d80c(&local_4c,0);
  FUN_8025d848(&local_4c,0);
  FUN_8025d888(0);
  FUN_8025d8c4(&local_4c,0x3c,0);
  FUN_8025d8c4(&local_4c,0x7d,0);
  uStack_c = (uint)*(ushort *)(puVar1 + 4);
  uStack_14 = (uint)*(ushort *)(puVar1 + 8);
  dVar4 = (double)FLOAT_803e8300;
  local_10 = 0x43300000;
  local_18 = 0x43300000;
  FUN_8025da64(dVar4,dVar4,(double)(float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e8308),
               (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e8308),dVar4,
               (double)FLOAT_803e82fc);
  FUN_802592d8(0);
  FUN_80259288(2);
  FUN_8025dbcc(0);
  FUN_8025da88(0,0,(uint)*(ushort *)(puVar1 + 4),(uint)*(ushort *)(puVar1 + 6));
  FUN_8025db88(0,0);
  FUN_8025a5bc(0);
  FUN_8025a608(4,0,0,1,0,0,2);
  local_60 = local_54;
  FUN_8025a2ec(4,&local_60);
  local_64 = local_58;
  FUN_8025a454(4,&local_64);
  FUN_8025a608(5,0,0,1,0,0,2);
  local_68 = local_54;
  FUN_8025a2ec(5,&local_68);
  local_6c = local_58;
  FUN_8025a454(5,&local_6c);
  FUN_8025b210();
  uVar3 = 0;
  *(undefined4 *)(DAT_803dd210 + 0x2c8) = 0;
  *(undefined4 *)(DAT_803dd210 + 0x2cc) = 0;
  FUN_8025b258(&LAB_80255430);
  FUN_8025b26c(&LAB_802554ac);
  FUN_8025c828(0,0,0,4);
  FUN_8025c828(1,1,1,4);
  FUN_8025c828(2,2,2,4);
  FUN_8025c828(3,3,3,4);
  FUN_8025c828(4,4,4,4);
  FUN_8025c828(5,5,5,4);
  FUN_8025c828(6,6,6,4);
  FUN_8025c828(7,7,7,4);
  FUN_8025c828(8,0xff,0xff,0xff);
  FUN_8025c828(9,0xff,0xff,0xff);
  FUN_8025c828(10,0xff,0xff,0xff);
  FUN_8025c828(0xb,0xff,0xff,0xff);
  FUN_8025c828(0xc,0xff,0xff,0xff);
  FUN_8025c828(0xd,0xff,0xff,0xff);
  FUN_8025c828(0xe,0xff,0xff,0xff);
  FUN_8025c828(0xf,0xff,0xff,0xff);
  FUN_8025ca04(1);
  FUN_8025c000(0,3);
  FUN_8025c754(7,0,0,7,0);
  FUN_8025c7a4(0,0x11,0);
  do {
    FUN_8025c584(uVar3,6);
    FUN_8025c5f0(uVar3,0);
    FUN_8025c65c(uVar3,0,0);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x10);
  FUN_8025c6b4(0,0,1,2,3);
  FUN_8025c6b4(1,0,0,0,3);
  FUN_8025c6b4(2,1,1,1,3);
  FUN_8025c6b4(3,2,2,2,3);
  uVar3 = 0;
  do {
    FUN_8025be80(uVar3);
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x10);
  FUN_8025be54(0);
  FUN_8025bb48(0,0,0);
  FUN_8025bb48(1,0,0);
  FUN_8025bb48(2,0,0);
  FUN_8025bb48(3,0,0);
  local_70 = local_54;
  FUN_8025ca38((double)FLOAT_803e8300,(double)FLOAT_803e82fc,(double)FLOAT_803e8304,
               (double)FLOAT_803e82fc,0,(uint3 *)&local_70);
  FUN_8025cbe8(0,0,(ushort *)0x0);
  FUN_8025cce8(0,4,5,0);
  FUN_8025cdec(1);
  FUN_8025ce2c(1);
  FUN_8025ce6c(1,3,1);
  FUN_8025cee4(1);
  FUN_8025d034(1);
  FUN_8025d074(0,0);
  FUN_8025cf24(0,0);
  FUN_8025d0c8(1,1);
  FUN_8025d100((uint)(byte)puVar1[0x18],
               (uint)((uint)*(ushort *)(puVar1 + 0x10) == (uint)*(ushort *)(puVar1 + 8) << 1));
  FUN_80259340(0,0,(uint)*(ushort *)(puVar1 + 4),(uint)*(ushort *)(puVar1 + 6));
  FUN_802594c0((uint)*(ushort *)(puVar1 + 4));
  uStack_14 = (uint)*(ushort *)(puVar1 + 8);
  uStack_c = (uint)*(ushort *)(puVar1 + 6);
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  FUN_8025971c((double)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e8308) /
                       (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e8308)));
  FUN_802596a0(3);
  FUN_80259858(puVar1[0x19],puVar1 + 0x1a,'\x01',puVar1 + 0x32);
  FUN_80259a80(0);
  FUN_80259674(0);
  FUN_80259d9c();
  FUN_80258d38(1);
  FUN_80258c94(1);
  FUN_80258d68(0);
  FUN_80258cb0(0,0,1,0xf);
  FUN_80258c6c(7,0);
  FUN_80258c80(1);
  FUN_80258d54(0,0);
  FUN_80258d84(1,7,1);
  FUN_8025dc78(0x23,0x16);
  FUN_8025e510();
  return;
}

