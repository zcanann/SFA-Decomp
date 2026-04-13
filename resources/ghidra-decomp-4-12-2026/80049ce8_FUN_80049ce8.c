// Function: FUN_80049ce8
// Entry: 80049ce8
// Size: 2132 bytes

void FUN_80049ce8(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_e8;
  float afStack_e4 [12];
  uint auStack_b4 [33];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar2 = FUN_80241df0();
  uVar3 = FUN_80241de8();
  FUN_80003494(uVar3 - 0x40000,0x802cd260,0x40000);
  FUN_80242114(uVar3 - 0x40000,0x40000);
  DAT_803dd964 = 0x40000;
  DAT_803dd958 = &DAT_802cd260;
  FUN_802420b0(0x802cd260,0x40000);
  DAT_803dd954 = (uint *)FUN_802554d0((int)DAT_803dd958,DAT_803dd964);
  DAT_803dd960 = DAT_803dd958;
  FUN_80259340(0,0,(uint)*(ushort *)(DAT_803dd970 + 1),(uint)*(ushort *)((int)DAT_803dd970 + 6));
  uStack_2c = (uint)*(ushort *)(DAT_803dd970 + 2);
  local_30 = 0x43300000;
  uStack_24 = (uint)*(ushort *)((int)DAT_803dd970 + 6);
  local_28 = 0x43300000;
  DAT_803dd938 = FUN_8025971c((double)((float)((double)CONCAT44(0x43300000,uStack_2c) -
                                              DOUBLE_803df700) /
                                      (float)((double)CONCAT44(0x43300000,uStack_24) -
                                             DOUBLE_803df700)));
  DAT_803dd96c = iVar2 + 0x1fU & 0xffffffe0;
  iVar2 = (*(ushort *)(DAT_803dd970 + 1) + 0xf & 0xfff0) * DAT_803dd938 * 2 + 0x1f;
  DAT_803dd968 = DAT_803dd96c + iVar2 & 0xffffffe0;
  uVar1 = DAT_803dd968 + iVar2 & 0xffffffe0;
  FUN_80241e00(uVar1);
  iVar2 = FUN_80241d0c(uVar1,uVar3,1);
  FUN_80241e00(iVar2);
  iVar2 = FUN_80241d7c(iVar2 + 0x1fU & 0xffffffe0,uVar3 & 0xffffffe0);
  FUN_80241cfc(iVar2);
  FUN_8024d51c(DAT_803dd970);
  FUN_8025665c((int *)auStack_b4,DAT_803dd96c,0x10000);
  FUN_80256744(auStack_b4);
  FUN_80256854(auStack_b4);
  FUN_80256738((int)DAT_803dd954,DAT_803dd964 - 0x4000,DAT_803dd964 * 3 >> 2);
  FUN_80256744(DAT_803dd954);
  FUN_80256854(DAT_803dd954);
  FUN_800138ac((undefined2 *)&DAT_80360390,&DAT_80360318,10,0xc);
  FUN_802464dc((undefined4 *)&DAT_803dd944);
  FUN_8024c8cc(FUN_80049a10);
  FUN_8024c910(FUN_800496cc);
  FUN_80256bc4(FUN_80049b64);
  dVar4 = (double)FLOAT_803df6f0;
  uStack_1c = (uint)*(ushort *)(DAT_803dd970 + 1);
  local_20 = 0x43300000;
  uStack_14 = (uint)*(ushort *)((int)DAT_803dd970 + 6);
  local_18 = 0x43300000;
  FUN_8025da64(dVar4,dVar4,(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df700)
               ,(double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df700),dVar4,
               (double)FLOAT_803df6f8);
  FUN_8025d100((uint)*(byte *)(DAT_803dd970 + 6),
               (uint)*(ushort *)(DAT_803dd970 + 2) - (uint)*(ushort *)(DAT_803dd970 + 4) >> 0x1f);
  FUN_8025da88(0,0,(uint)*(ushort *)(DAT_803dd970 + 1),(uint)*(ushort *)((int)DAT_803dd970 + 6));
  FUN_802594c0((uint)*(ushort *)(DAT_803dd970 + 1));
  if (*(char *)((int)DAT_803dd970 + 0x19) == '\0') {
    FUN_8025cf24(0,0);
    FUN_8025d034(0);
  }
  else {
    FUN_8025cf24(2,0);
    FUN_8025d034(1);
  }
  DAT_803dd94c = DAT_803dd96c;
  DAT_803dd950 = DAT_803dd968;
  FUN_8024ddd4(DAT_803dd96c);
  FUN_80259a80(0);
  FUN_8024de40(1);
  FUN_8024dcb8();
  FUN_8024d054();
  FUN_8024d054();
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_80257ba8(0,9,1,3,0);
  FUN_80257ba8(0,0xb,1,5,0);
  FUN_80257ba8(0,0xd,1,3,7);
  FUN_80257ba8(1,9,1,3,2);
  FUN_80257ba8(1,0xb,1,5,0);
  FUN_80257ba8(1,0xd,1,4,0);
  FUN_80257ba8(2,9,1,4,0);
  FUN_80257ba8(2,10,0,4,0);
  FUN_80257ba8(2,0xb,1,5,0);
  FUN_80257ba8(2,0xd,1,4,0);
  FUN_80257ba8(2,0xe,1,4,0);
  FUN_80257ba8(3,9,1,3,8);
  FUN_80257ba8(3,0x19,1,1,0);
  FUN_80257ba8(3,0xb,1,3,0);
  FUN_80257ba8(3,0xd,1,3,10);
  FUN_80257ba8(3,0xe,1,3,10);
  FUN_80257ba8(3,0xf,1,3,10);
  FUN_80257ba8(3,0x10,1,3,10);
  FUN_80257ba8(4,9,1,4,0);
  FUN_80257ba8(4,0xb,1,5,0);
  FUN_80257ba8(4,0xd,1,3,7);
  FUN_80257ba8(4,10,0,4,0);
  FUN_80257ba8(5,9,1,3,3);
  FUN_80257ba8(5,10,0,1,0);
  FUN_80257ba8(5,0xb,1,3,0);
  FUN_80257ba8(5,0xd,1,3,8);
  FUN_80257ba8(5,0xe,1,3,8);
  FUN_80257ba8(5,0xf,1,3,8);
  FUN_80257ba8(5,0x10,1,3,8);
  FUN_80257ba8(6,9,1,3,8);
  FUN_80257ba8(6,10,0,1,0);
  FUN_80257ba8(6,0xb,1,3,0);
  FUN_80257ba8(6,0xd,1,3,10);
  FUN_80257ba8(6,0xe,1,3,10);
  FUN_80257ba8(6,0xf,1,3,10);
  FUN_80257ba8(6,0x10,1,3,10);
  FUN_80257ba8(7,9,1,3,0);
  FUN_80257ba8(7,10,0,1,0);
  FUN_80257ba8(7,0xb,1,3,0);
  FUN_80257ba8(7,0xd,1,3,10);
  FUN_80257ba8(7,0xe,1,3,10);
  FUN_80257ba8(7,0xf,1,3,10);
  FUN_80257ba8(7,0x10,1,3,10);
  DAT_803dd974 = 0;
  FUN_80259288(0);
  local_e8 = DAT_803dc230;
  FUN_802597f0((undefined *)&local_e8,0xffffff);
  FUN_8025cce8(0,1,0,5);
  FUN_8025a5bc(1);
  FUN_8025a608(0,0,0,1,0,0,2);
  DAT_803dd980 = 1;
  DAT_803dd97c = 3;
  DAT_803dd978 = 1;
  FUN_8007048c(1,3,1);
  FUN_80070434(1);
  FUN_80259224(0,1,1);
  FUN_802475b8(afStack_e4);
  FUN_8025d80c(afStack_e4,0);
  FUN_8025d8c4(afStack_e4,0x1e,0);
  FUN_8025d8c4(afStack_e4,0x21,0);
  FUN_8025d888(0);
  FUN_80247dfc((double)FLOAT_803df714,(double)FLOAT_803df718,(double)FLOAT_803df6f0,
               (double)FLOAT_803df70c,(double)FLOAT_803df6f8,(double)FLOAT_803df710,
               (float *)&DAT_803974e0);
  FUN_8025898c(1,8);
  return;
}

