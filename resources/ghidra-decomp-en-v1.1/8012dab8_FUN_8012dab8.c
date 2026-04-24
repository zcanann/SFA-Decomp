// Function: FUN_8012dab8
// Entry: 8012dab8
// Size: 496 bytes

void FUN_8012dab8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort uVar2;
  short sVar3;
  int iVar1;
  int iVar4;
  byte *pbVar5;
  undefined *puVar6;
  int iVar7;
  short sVar8;
  undefined8 uVar9;
  int iStack_28;
  int iStack_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  FUN_80286840();
  if ((DAT_803de3f4 != 0) && (DAT_803de3f6 == 0)) {
    iVar4 = FUN_80019b4c();
    uVar9 = FUN_80019b54((uint)DAT_803de3fb,3);
    pbVar5 = (byte *)FUN_800191fc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  DAT_803dc6c8,DAT_803dc6c4,param_11,param_12,param_13,param_14,
                                  param_15,param_16);
    puVar6 = FUN_80017400(0x49);
    DAT_8033caa0 = DAT_803a974c;
    DAT_8033caa4 = DAT_803a9750;
    DAT_8033caa8 = DAT_803a9754;
    DAT_8033caac = DAT_803a9758;
    DAT_8033cab0 = DAT_803a975c;
    uVar2 = DAT_803de3f4;
    if (0x7f < DAT_803de3f4) {
      uVar2 = 0xff - DAT_803de3f4;
    }
    sVar3 = uVar2 * 0xf;
    if (0xff < sVar3) {
      sVar3 = 0xff;
    }
    uVar2 = DAT_803de3f4;
    if (0x7f < DAT_803de3f4) {
      uVar2 = 0xff - DAT_803de3f4;
    }
    iVar7 = (short)uVar2 + -0x14;
    if ((short)iVar7 < 0) {
      iVar7 = 0;
    }
    sVar8 = (short)(iVar7 << 4);
    if (0x10e < sVar8) {
      sVar8 = 0x10e;
    }
    FUN_80019884(*(ushort *)(puVar6 + 2),*(ushort *)(puVar6 + 10),1);
    FUN_800163fc(pbVar5,0x49,0,0,&local_1c,&local_20,&iStack_24,&iStack_28);
    FUN_8001983c(1);
    iVar1 = (short)(local_20._2_2_ - local_1c._2_2_) + 0x28;
    iVar7 = (int)sVar8;
    if (iVar1 < iVar7) {
      iVar7 = iVar1;
    }
    uVar2 = (ushort)iVar7;
    if ((short)uVar2 < 0) {
      uVar2 = 0;
    }
    *(ushort *)(puVar6 + 8) = uVar2 & 0xfffe;
    *(short *)(puVar6 + 0x14) = 0x140 - ((short)uVar2 >> 1);
    FUN_80019884(*(ushort *)(puVar6 + 2),*(ushort *)(puVar6 + 10),2);
    FUN_80019940(0xff,0xff,0xff,(byte)sVar3);
    puVar6[0x1e] = (byte)sVar3;
    FUN_800161c4(pbVar5,0x49);
    FUN_8001983c(2);
    FUN_80019b54(iVar4,3);
  }
  FUN_8028688c();
  return;
}

