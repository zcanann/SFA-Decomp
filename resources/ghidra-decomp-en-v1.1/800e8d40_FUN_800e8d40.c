// Function: FUN_800e8d40
// Entry: 800e8d40
// Size: 736 bytes

void FUN_800e8d40(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  int iVar5;
  short *psVar6;
  char *pcVar7;
  char cVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar3 = DAT_802c28f8;
  uVar2 = DAT_802c28f4;
  uVar1 = DAT_802c28f0;
  pcVar7 = (char *)((ulonglong)uVar10 >> 0x20);
  FUN_800033a8(-0x7fc5c0f8,0,0xf70);
  if ((*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803de110,0,0x6ec);
  }
  DAT_803a3f28 = 0;
  DAT_803a3f08 = 0xc;
  DAT_803a3f09 = 0xc;
  DAT_803a3f0e = 0x19;
  DAT_803a3f0c = 0;
  DAT_803a3f12 = 1;
  DAT_803a459a = 0xff;
  DAT_803a3f14 = 0xc;
  DAT_803a3f15 = 0xc;
  DAT_803a3f1a = 0x19;
  DAT_803a3f18 = 0;
  DAT_803a3f1e = 1;
  DAT_803a45aa = 0xff;
  DAT_803a3f21 = 0x14;
  DAT_803a45ac = 0xffff;
  DAT_803a45b0 = FLOAT_803e1348;
  DAT_803a45b4 = 0xffff;
  DAT_803a45b6 = 0xffff;
  DAT_803a45ba = 0xffff;
  DAT_803a45bc = 0xffff;
  DAT_803a45be = 0xffff;
  DAT_803a45c0 = 0xffff;
  DAT_803a45c2 = 0xffff;
  DAT_803a45f1 = 0xff;
  DAT_803a45f2 = 0xff;
  DAT_803a45f3 = 0xff;
  DAT_803a45f0 = 9;
  DAT_803a3f2b = 0;
  DAT_803a3f29 = 1;
  iVar5 = 0;
  psVar6 = &DAT_80312370;
  do {
    if (*psVar6 != 0) {
      (**(code **)(*DAT_803dd72c + 0x44))(iVar5,1);
    }
    psVar6 = psVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x78);
  FUN_800e927c(7,0,1);
  FUN_800e927c(7,2,1);
  FUN_800e927c(7,3,1);
  FUN_800e927c(7,5,1);
  FUN_800e927c(7,10,1);
  FUN_800e927c(0x1d,0,1);
  FUN_800e927c(0x1d,0x1f,1);
  FUN_800e927c(0x13,0,1);
  FUN_800e927c(0x13,0x16,1);
  FUN_800201ac(0x967,1);
  (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = uVar1;
  (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = uVar2;
  (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = uVar3;
  DAT_803a4465 = 1;
  if (pcVar7 == (char *)0x0) {
    DAT_803a3f24 = 0x46;
    DAT_803a3f25 = 0x4f;
    DAT_803a3f26 = 0x58;
    DAT_803a3f27 = 0;
    pcVar7 = (char *)0x0;
  }
  else {
    pcVar4 = &DAT_803a3f24;
    do {
      cVar8 = *pcVar7;
      pcVar7 = pcVar7 + 1;
      *pcVar4 = cVar8;
      pcVar4 = pcVar4 + 1;
    } while (cVar8 != '\0');
  }
  uVar9 = FUN_80003494(DAT_803de110,0x803a3f08,0x6ec);
  cVar8 = (char)uVar10;
  if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, pcVar7 != (char *)0x0)) {
    FUN_8007dca0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)uVar10 & 0xff,
                 DAT_803de110,&DAT_803a3e24);
  }
  FUN_8028688c();
  return;
}

