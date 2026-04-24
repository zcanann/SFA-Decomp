// Function: FUN_802b6ad4
// Entry: 802b6ad4
// Size: 1140 bytes

void FUN_802b6ad4(void)

{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  ushort uVar5;
  int iVar4;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  short *psVar10;
  
  psVar2 = (short *)FUN_802860dc();
  iVar8 = *(int *)(psVar2 + 0x5c);
  DAT_803de459 = 0;
  FUN_80037200(psVar2,0);
  FUN_80037200(psVar2,0x25);
  FUN_8002b8c8(psVar2,0x3c);
  FUN_80037964(psVar2,0x14);
  *(code **)(psVar2 + 0x5e) = FUN_802b2da4;
  *(undefined4 *)(psVar2 + 0x26) = 0;
  *(undefined4 *)(iVar8 + 0x7f8) = 0;
  uVar3 = (**(code **)(*DAT_803dcaac + 0x8c))();
  *(undefined4 *)(iVar8 + 0x35c) = uVar3;
  uVar5 = (**(code **)(*DAT_803dcaac + 0x74))();
  *(ushort *)(iVar8 + 0x81a) = uVar5 & 0xff;
  FUN_8002b884(psVar2,(int)*(short *)(iVar8 + 0x81a));
  iVar4 = (**(code **)(*DAT_803dcaac + 0x90))();
  *psVar2 = (short)((int)*(char *)(iVar4 + 0xc) << 8);
  *(short *)(iVar8 + 0x478) = *psVar2;
  *(short *)(iVar8 + 0x484) = *psVar2;
  *(int *)(iVar8 + 0x494) = (int)*psVar2;
  fVar1 = FLOAT_803e7ee0;
  *(float *)(iVar8 + 0x77c) = FLOAT_803e7ee0;
  *(undefined2 *)(iVar8 + 0x80c) = 0xffff;
  *(undefined2 *)(iVar8 + 0x80a) = 0xffff;
  *(float *)(iVar8 + 0x82c) = fVar1;
  *(float *)(iVar8 + 0x834) = fVar1;
  *(float *)(iVar8 + 0x830) = FLOAT_803e8144;
  *(byte *)(iVar8 + 0x3f1) = *(byte *)(iVar8 + 0x3f1) & 0xfe | 1;
  *(float *)(iVar8 + 0x880) = FLOAT_803e7fa4;
  *(undefined *)(iVar8 + 0x8a3) = 3;
  *(undefined *)(iVar8 + 0x8a4) = 4;
  *(undefined *)(iVar8 + 0x8a5) = 5;
  *(undefined *)(iVar8 + 0x8a7) = 6;
  *(undefined *)(iVar8 + 0x8a6) = *(undefined *)(iVar8 + 0x8a3);
  *(undefined *)(iVar8 + 0x8bf) = 0;
  (**(code **)(*DAT_803dca8c + 4))(psVar2,iVar8,0x42,1);
  *(int *)(iVar8 + 0x27c) = iVar8 + 0x6f0;
  iVar4 = iVar8 + 4;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar4,1,0x400a7,1);
  (**(code **)(*DAT_803dcaa8 + 8))(iVar4,1,&DAT_80332ff0,&FLOAT_803dc6c0,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar4,2,&DAT_80332fd8,&DAT_803dc6b8,&DAT_803dc6a4);
  *(undefined *)(iVar8 + 0x25c) = 100;
  FUN_802ab5a4(psVar2,iVar8,0xff);
  *(undefined2 *)(*(int *)(psVar2 + 0x2a) + 0xb2) = 0x29;
  *(undefined *)(psVar2 + 0x1b) = 0xff;
  iVar4 = *(int *)(psVar2 + 0x32);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x4008;
  }
  (**(code **)(*DAT_803dca68 + 0x14))();
  iVar9 = 0;
  DAT_803de444 = 0;
  *(byte *)(iVar8 + 0x3f4) = *(byte *)(iVar8 + 0x3f4) & 0xbf | 0x40;
  *(undefined **)(iVar8 + 0x3f8) = &DAT_80333050;
  *(undefined **)(iVar8 + 0x3dc) = &DAT_80333714;
  *(undefined *)(iVar8 + 0x8a8) = 0x1c;
  *(undefined **)(iVar8 + 0x450) = &DAT_80333310;
  *(undefined *)(iVar8 + 0x8d0) = 0x29;
  *(undefined **)(iVar8 + 0x454) = &DAT_803333b4;
  *(undefined *)(iVar8 + 0x8d1) = 0x29;
  *(undefined **)(iVar8 + 0x458) = &DAT_80333458;
  *(undefined *)(iVar8 + 0x8d2) = 0x2e;
  *(undefined **)(iVar8 + 0x45c) = &DAT_80333510;
  *(undefined *)(iVar8 + 0x8d3) = 0x29;
  *(undefined **)(iVar8 + 0x460) = &DAT_803335b4;
  *(undefined *)(iVar8 + 0x8d4) = 0x2e;
  *(float *)(iVar8 + 0x7e0) = FLOAT_803e7ed8;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar8 + 0x8a8); iVar4 = iVar4 + 1) {
    uVar3 = FUN_80023cc8(0x800,0x1a,0);
    *(undefined4 *)(*(int *)(iVar8 + 0x3dc) + iVar9 + 100) = uVar3;
    iVar6 = *(int *)(iVar8 + 0x3dc) + iVar9;
    FUN_8002c60c(psVar2,(int)psVar2[0x23],iVar6 + 0x60,
                 (int)*(short *)(&DAT_803336bc + *(short *)(iVar6 + 2) * 2),0);
    iVar9 = iVar9 + 0xb0;
  }
  FUN_802aabe4(psVar2);
  DAT_803de4b2 = 0x2d;
  uVar7 = 0;
  DAT_803de448 = 0;
  psVar10 = &DAT_80334a54;
  do {
    iVar4 = FUN_8001ffb4((int)*psVar10);
    if (iVar4 != 0) {
      *(byte *)(iVar8 + 0x8c7) = *(byte *)(iVar8 + 0x8c7) | (byte)(1 << uVar7);
    }
    psVar10 = psVar10 + 1;
    uVar7 = uVar7 + 1;
  } while (uVar7 < 0xb);
  if (*(short *)(iVar8 + 0x81a) == 0) {
    *(float *)(iVar8 + 0x7dc) = FLOAT_803e8168;
    *(float *)(iVar8 + 0x874) = FLOAT_803e816c;
  }
  else {
    *(float *)(iVar8 + 0x7dc) = FLOAT_803e8170;
    *(float *)(iVar8 + 0x874) = FLOAT_803e8174;
  }
  DAT_803de420 = FUN_80026cfc(&DAT_803dc668,1);
  *(code **)(psVar2 + 0x84) = FUN_8029560c;
  if (DAT_803de424 != 0) {
    if (DAT_803de424 < 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = DAT_803de424;
      if (0x50 < DAT_803de424) {
        iVar4 = 0x50;
      }
    }
    *(char *)(*(int *)(*(int *)(psVar2 + 0x5c) + 0x35c) + 1) = (char)iVar4;
    if (DAT_803de424 < 0) {
      DAT_803de424 = 0;
    }
    else {
      iVar4 = (int)*(char *)(*(int *)(*(int *)(psVar2 + 0x5c) + 0x35c) + 1);
      if (iVar4 < DAT_803de424) {
        DAT_803de424 = iVar4;
      }
    }
    **(undefined **)(*(int *)(psVar2 + 0x5c) + 0x35c) = (char)DAT_803de424;
    DAT_803de424 = 0;
  }
  DAT_803de428 = 0;
  FUN_80286128();
  return;
}

