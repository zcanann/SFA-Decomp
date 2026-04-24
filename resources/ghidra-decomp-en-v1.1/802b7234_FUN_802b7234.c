// Function: FUN_802b7234
// Entry: 802b7234
// Size: 1140 bytes

void FUN_802b7234(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  ushort uVar7;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  undefined8 uVar13;
  
  psVar2 = (short *)FUN_80286840();
  iVar10 = *(int *)(psVar2 + 0x5c);
  DAT_803df0d9 = 0;
  FUN_800372f8((int)psVar2,0);
  FUN_800372f8((int)psVar2,0x25);
  FUN_8002b9a0((int)psVar2,'<');
  FUN_80037a5c((int)psVar2,0x14);
  *(code **)(psVar2 + 0x5e) = FUN_802b3504;
  psVar2[0x26] = 0;
  psVar2[0x27] = 0;
  *(undefined4 *)(iVar10 + 0x7f8) = 0;
  uVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
  *(undefined4 *)(iVar10 + 0x35c) = uVar3;
  uVar7 = (**(code **)(*DAT_803dd72c + 0x74))();
  *(ushort *)(iVar10 + 0x81a) = uVar7 & 0xff;
  FUN_8002b95c((int)psVar2,(int)*(short *)(iVar10 + 0x81a));
  iVar4 = (**(code **)(*DAT_803dd72c + 0x90))();
  *psVar2 = (short)((int)*(char *)(iVar4 + 0xc) << 8);
  *(short *)(iVar10 + 0x478) = *psVar2;
  *(short *)(iVar10 + 0x484) = *psVar2;
  *(int *)(iVar10 + 0x494) = (int)*psVar2;
  fVar1 = FLOAT_803e8b78;
  *(float *)(iVar10 + 0x77c) = FLOAT_803e8b78;
  *(undefined2 *)(iVar10 + 0x80c) = 0xffff;
  *(undefined2 *)(iVar10 + 0x80a) = 0xffff;
  *(float *)(iVar10 + 0x82c) = fVar1;
  *(float *)(iVar10 + 0x834) = fVar1;
  *(float *)(iVar10 + 0x830) = FLOAT_803e8ddc;
  *(byte *)(iVar10 + 0x3f1) = *(byte *)(iVar10 + 0x3f1) & 0xfe | 1;
  *(float *)(iVar10 + 0x880) = FLOAT_803e8c3c;
  *(undefined *)(iVar10 + 0x8a3) = 3;
  *(undefined *)(iVar10 + 0x8a4) = 4;
  *(undefined *)(iVar10 + 0x8a5) = 5;
  *(undefined *)(iVar10 + 0x8a7) = 6;
  *(undefined *)(iVar10 + 0x8a6) = *(undefined *)(iVar10 + 0x8a3);
  *(undefined *)(iVar10 + 0x8bf) = 0;
  (**(code **)(*DAT_803dd70c + 4))(psVar2,iVar10,0x42,1);
  *(int *)(iVar10 + 0x27c) = iVar10 + 0x6f0;
  iVar4 = iVar10 + 4;
  (**(code **)(*DAT_803dd728 + 4))(iVar4,1,0x400a7,1);
  (**(code **)(*DAT_803dd728 + 8))(iVar4,1,&DAT_80333c50,&FLOAT_803dd328,1);
  iVar8 = *DAT_803dd728;
  (**(code **)(iVar8 + 0xc))(iVar4,2,&DAT_80333c38,&DAT_803dd320,&DAT_803dd30c);
  *(undefined *)(iVar10 + 0x25c) = 100;
  FUN_802abd04((int)psVar2,iVar10,0xff);
  *(undefined2 *)(*(int *)(psVar2 + 0x2a) + 0xb2) = 0x29;
  *(undefined *)(psVar2 + 0x1b) = 0xff;
  iVar4 = *(int *)(psVar2 + 0x32);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x4008;
  }
  uVar13 = (**(code **)(*DAT_803dd6e8 + 0x14))();
  iVar11 = 0;
  DAT_803df0c4 = 0;
  *(byte *)(iVar10 + 0x3f4) = *(byte *)(iVar10 + 0x3f4) & 0xbf | 0x40;
  *(undefined **)(iVar10 + 0x3f8) = &DAT_80333cb0;
  *(undefined **)(iVar10 + 0x3dc) = &DAT_80334374;
  *(undefined *)(iVar10 + 0x8a8) = 0x1c;
  *(undefined **)(iVar10 + 0x450) = &DAT_80333f70;
  *(undefined *)(iVar10 + 0x8d0) = 0x29;
  *(undefined **)(iVar10 + 0x454) = &DAT_80334014;
  *(undefined *)(iVar10 + 0x8d1) = 0x29;
  *(undefined **)(iVar10 + 0x458) = &DAT_803340b8;
  *(undefined *)(iVar10 + 0x8d2) = 0x2e;
  *(undefined **)(iVar10 + 0x45c) = &DAT_80334170;
  *(undefined *)(iVar10 + 0x8d3) = 0x29;
  *(undefined **)(iVar10 + 0x460) = &DAT_80334214;
  *(undefined *)(iVar10 + 0x8d4) = 0x2e;
  *(float *)(iVar10 + 0x7e0) = FLOAT_803e8b70;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar10 + 0x8a8); iVar4 = iVar4 + 1) {
    iVar5 = FUN_80023d8c(0x800,0x1a);
    *(int *)(*(int *)(iVar10 + 0x3dc) + iVar11 + 100) = iVar5;
    iVar5 = *(int *)(iVar10 + 0x3dc) + iVar11;
    uVar13 = FUN_8002c6e4(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)psVar2
                          ,(int)psVar2[0x23],(uint *)(iVar5 + 0x60),
                          (int)*(short *)(&DAT_8033431c + *(short *)(iVar5 + 2) * 2),0,iVar8,in_r9,
                          in_r10);
    iVar11 = iVar11 + 0xb0;
  }
  FUN_802ab344(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803df132 = 0x2d;
  uVar9 = 0;
  DAT_803df0c8 = 0;
  psVar12 = &DAT_803356b4;
  do {
    uVar6 = FUN_80020078((int)*psVar12);
    if (uVar6 != 0) {
      *(byte *)(iVar10 + 0x8c7) = *(byte *)(iVar10 + 0x8c7) | (byte)(1 << uVar9);
    }
    psVar12 = psVar12 + 1;
    uVar9 = uVar9 + 1;
  } while (uVar9 < 0xb);
  if (*(short *)(iVar10 + 0x81a) == 0) {
    *(float *)(iVar10 + 0x7dc) = FLOAT_803e8e00;
    *(float *)(iVar10 + 0x874) = FLOAT_803e8e04;
  }
  else {
    *(float *)(iVar10 + 0x7dc) = FLOAT_803e8e08;
    *(float *)(iVar10 + 0x874) = FLOAT_803e8e0c;
  }
  DAT_803df0a0 = FUN_80026dc0();
  *(code **)(psVar2 + 0x84) = FUN_80295d6c;
  if (DAT_803df0a4 != 0) {
    if (DAT_803df0a4 < 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = DAT_803df0a4;
      if (0x50 < DAT_803df0a4) {
        iVar4 = 0x50;
      }
    }
    *(char *)(*(int *)(*(int *)(psVar2 + 0x5c) + 0x35c) + 1) = (char)iVar4;
    if (DAT_803df0a4 < 0) {
      DAT_803df0a4 = 0;
    }
    else {
      iVar4 = (int)*(char *)(*(int *)(*(int *)(psVar2 + 0x5c) + 0x35c) + 1);
      if (iVar4 < DAT_803df0a4) {
        DAT_803df0a4 = iVar4;
      }
    }
    **(undefined **)(*(int *)(psVar2 + 0x5c) + 0x35c) = (char)DAT_803df0a4;
    DAT_803df0a4 = 0;
  }
  DAT_803df0a8 = 0;
  FUN_8028688c();
  return;
}

