// Function: FUN_80049b6c
// Entry: 80049b6c
// Size: 2132 bytes

void FUN_80049b6c(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_e8;
  undefined auStack228 [48];
  undefined auStack180 [132];
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  iVar2 = FUN_802416f8();
  uVar3 = FUN_802416f0();
  FUN_80003494(uVar3 - 0x40000,&DAT_802cc6a0,0x40000);
  FUN_80241a1c(uVar3 - 0x40000,0x40000);
  DAT_803dcce4 = 0x40000;
  DAT_803dccd8 = &DAT_802cc6a0;
  FUN_802419b8();
  DAT_803dccd4 = FUN_80254d6c(DAT_803dccd8,DAT_803dcce4);
  DAT_803dcce0 = DAT_803dccd8;
  FUN_80258bdc(0,0,*(undefined2 *)(DAT_803dccf0 + 4),*(undefined2 *)(DAT_803dccf0 + 6));
  uStack44 = (uint)*(ushort *)(DAT_803dccf0 + 8);
  local_30 = 0x43300000;
  uStack36 = (uint)*(ushort *)(DAT_803dccf0 + 6);
  local_28 = 0x43300000;
  DAT_803dccb8 = FUN_80258fb8((double)((float)((double)CONCAT44(0x43300000,uStack44) -
                                              DOUBLE_803dea80) /
                                      (float)((double)CONCAT44(0x43300000,uStack36) -
                                             DOUBLE_803dea80)));
  DAT_803dccec = iVar2 + 0x1fU & 0xffffffe0;
  iVar2 = (*(ushort *)(DAT_803dccf0 + 4) + 0xf & 0xfff0) * DAT_803dccb8 * 2 + 0x1f;
  DAT_803dcce8 = DAT_803dccec + iVar2 & 0xffffffe0;
  uVar1 = DAT_803dcce8 + iVar2 & 0xffffffe0;
  FUN_80241708(uVar1);
  iVar2 = FUN_80241614(uVar1,uVar3,1);
  FUN_80241708();
  FUN_80241684(iVar2 + 0x1fU & 0xffffffe0,uVar3 & 0xffffffe0);
  FUN_80241604();
  FUN_8024cdb8(DAT_803dccf0);
  FUN_80255ef8(auStack180,DAT_803dccec,0x10000);
  FUN_80255fe0(auStack180);
  FUN_802560f0(auStack180);
  FUN_80255fd4(DAT_803dccd4,DAT_803dcce4 + -0x4000,(uint)(DAT_803dcce4 * 3) >> 2);
  FUN_80255fe0(DAT_803dccd4);
  FUN_802560f0(DAT_803dccd4);
  FUN_8001388c(&DAT_8035f730,&DAT_8035f6b8,10,0xc);
  FUN_80245d78(&DAT_803dccc4);
  FUN_8024c168(FUN_80049894);
  FUN_8024c1ac(FUN_80049550);
  FUN_80256460(FUN_800499e8);
  dVar4 = (double)FLOAT_803dea70;
  uStack28 = (uint)*(ushort *)(DAT_803dccf0 + 4);
  local_20 = 0x43300000;
  uStack20 = (uint)*(ushort *)(DAT_803dccf0 + 8);
  local_18 = 0x43300000;
  FUN_8025d300(dVar4,dVar4,(double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dea80),
               (double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803dea80),dVar4,
               (double)FLOAT_803dea78);
  FUN_8025c99c(*(undefined *)(DAT_803dccf0 + 0x18),
               (uint)*(ushort *)(DAT_803dccf0 + 8) - (uint)*(ushort *)(DAT_803dccf0 + 0x10) >> 0x1f)
  ;
  FUN_8025d324(0,0,*(undefined2 *)(DAT_803dccf0 + 4),*(undefined2 *)(DAT_803dccf0 + 6));
  FUN_80258d5c(*(undefined2 *)(DAT_803dccf0 + 4),DAT_803dccb8 & 0xffff);
  if (*(char *)(DAT_803dccf0 + 0x19) == '\0') {
    FUN_8025c7c0(0,0);
    FUN_8025c8d0(0);
  }
  else {
    FUN_8025c7c0(2,0);
    FUN_8025c8d0(1);
  }
  DAT_803dcccc = DAT_803dccec;
  DAT_803dccd0 = DAT_803dcce8;
  FUN_8024d670();
  FUN_8025931c(0);
  FUN_8024d6dc(1);
  FUN_8024d554();
  FUN_8024c8f0();
  FUN_8024c8f0();
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  FUN_80257444(0,9,1,3,0);
  FUN_80257444(0,0xb,1,5,0);
  FUN_80257444(0,0xd,1,3,7);
  FUN_80257444(1,9,1,3,2);
  FUN_80257444(1,0xb,1,5,0);
  FUN_80257444(1,0xd,1,4,0);
  FUN_80257444(2,9,1,4,0);
  FUN_80257444(2,10,0,4,0);
  FUN_80257444(2,0xb,1,5,0);
  FUN_80257444(2,0xd,1,4,0);
  FUN_80257444(2,0xe,1,4,0);
  FUN_80257444(3,9,1,3,8);
  FUN_80257444(3,0x19,1,1,0);
  FUN_80257444(3,0xb,1,3,0);
  FUN_80257444(3,0xd,1,3,10);
  FUN_80257444(3,0xe,1,3,10);
  FUN_80257444(3,0xf,1,3,10);
  FUN_80257444(3,0x10,1,3,10);
  FUN_80257444(4,9,1,4,0);
  FUN_80257444(4,0xb,1,5,0);
  FUN_80257444(4,0xd,1,3,7);
  FUN_80257444(4,10,0,4,0);
  FUN_80257444(5,9,1,3,3);
  FUN_80257444(5,10,0,1,0);
  FUN_80257444(5,0xb,1,3,0);
  FUN_80257444(5,0xd,1,3,8);
  FUN_80257444(5,0xe,1,3,8);
  FUN_80257444(5,0xf,1,3,8);
  FUN_80257444(5,0x10,1,3,8);
  FUN_80257444(6,9,1,3,8);
  FUN_80257444(6,10,0,1,0);
  FUN_80257444(6,0xb,1,3,0);
  FUN_80257444(6,0xd,1,3,10);
  FUN_80257444(6,0xe,1,3,10);
  FUN_80257444(6,0xf,1,3,10);
  FUN_80257444(6,0x10,1,3,10);
  FUN_80257444(7,9,1,3,0);
  FUN_80257444(7,10,0,1,0);
  FUN_80257444(7,0xb,1,3,0);
  FUN_80257444(7,0xd,1,3,10);
  FUN_80257444(7,0xe,1,3,10);
  FUN_80257444(7,0xf,1,3,10);
  FUN_80257444(7,0x10,1,3,10);
  DAT_803dccf4 = 0;
  FUN_80258b24(0);
  local_e8 = DAT_803db5d0;
  FUN_8025908c(&local_e8,0xffffff);
  FUN_8025c584(0,1,0,5);
  FUN_80259e58(1);
  FUN_80259ea4(0,0,0,1,0,0,2);
  DAT_803dcd00 = 1;
  DAT_803dccfc = 3;
  DAT_803dccf8 = 1;
  FUN_80070310(1,3,1);
  FUN_800702b8(1);
  FUN_80258ac0(0,1,1);
  FUN_80246e54(auStack228);
  FUN_8025d0a8(auStack228,0);
  FUN_8025d160(auStack228,0x1e,0);
  FUN_8025d160(auStack228,0x21,0);
  FUN_8025d124(0);
  FUN_80247698((double)FLOAT_803dea94,(double)FLOAT_803dea98,(double)FLOAT_803dea70,
               (double)FLOAT_803dea8c,(double)FLOAT_803dea78,(double)FLOAT_803dea90,&DAT_80396880);
  FUN_80258228(1,8);
  return;
}

