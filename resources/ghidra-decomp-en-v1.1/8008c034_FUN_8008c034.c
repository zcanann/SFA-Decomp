// Function: FUN_8008c034
// Entry: 8008c034
// Size: 1120 bytes

void FUN_8008c034(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int *piVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined4 in_r6;
  int iVar10;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar11;
  int iVar12;
  double dVar13;
  
  if (DAT_803dddac != (int *)0x0) {
    if (DAT_803dddac != (int *)0x0) {
      if (*DAT_803dddac != 0) {
        FUN_80054484();
      }
      if (DAT_803dddac[1] != 0) {
        FUN_80054484();
      }
      FUN_800238c4(DAT_803dddac[2]);
      FUN_800238c4(DAT_803dddac[4]);
      FUN_800238c4((uint)DAT_803dddac);
    }
    DAT_803dddac = (int *)0x0;
  }
  DAT_803dddac = (int *)FUN_80023d8c(600,0x17);
  uVar9 = 600;
  FUN_800033a8((int)DAT_803dddac,0,600);
  *(undefined *)(DAT_803dddac + 0x94) = 0xff;
  uVar7 = FUN_80022264(0,0x1c);
  piVar1 = DAT_803dddac;
  DAT_803dddac[0x86] = uVar7;
  *(undefined *)((int)DAT_803dddac + 0x252) = 0xc;
  *(undefined *)((int)DAT_803dddac + 0x253) = 0;
  DAT_803dddac[0x83] = (int)FLOAT_803dfd74;
  DAT_803dddac[0x84] = 0xb4;
  DAT_803dddac[7] = (int)FLOAT_803dfd78;
  dVar13 = (double)(float)((double)CONCAT44(0x43300000,DAT_803dddac[0x84] ^ 0x80000000) -
                          DOUBLE_803dfd10);
  DAT_803dddac[0x85] = (int)(float)(dVar13 / (double)FLOAT_803dfce0);
  DAT_803dddac[0x87] = 0xc38;
  DAT_803dddac[0x88] = 0xc38;
  DAT_803dddac[0x89] = 0xc38;
  DAT_803dddac[0x8a] = 0xc38;
  DAT_803dddac[0x8b] = 0xc38;
  DAT_803dddac[0x8c] = 0xc38;
  DAT_803dddac[0x8d] = 0xc38;
  DAT_803dddac[0x8e] = 0xc38;
  iVar8 = FUN_80054ed0(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       DAT_803dddac[0x87],piVar1,uVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
  piVar1 = DAT_803dddac;
  *DAT_803dddac = iVar8;
  iVar8 = FUN_80054ed0(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       DAT_803dddac[0x88],piVar1,uVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
  DAT_803dddac[1] = iVar8;
  DAT_803dddac[5] = 0xc38;
  DAT_803dddac[6] = 0xc38;
  iVar11 = *DAT_803dddac;
  iVar8 = FUN_80054e14((uint)*(ushort *)(iVar11 + 10),(uint)*(ushort *)(iVar11 + 0xc),6,'\0',0,1,0,1
                       ,1);
  DAT_803dddac[2] = iVar8;
  iVar8 = FUN_80054e14((uint)*(ushort *)(iVar11 + 10),(uint)*(ushort *)(iVar11 + 0xc),6,'\0',0,1,0,1
                       ,1);
  DAT_803dddac[4] = iVar8;
  fVar6 = FLOAT_803dfd80;
  fVar5 = FLOAT_803dfd7c;
  fVar4 = FLOAT_803dfcec;
  fVar3 = FLOAT_803dfcdc;
  fVar2 = FLOAT_803dfcd8;
  iVar11 = 0;
  iVar8 = 0;
  do {
    iVar10 = 0;
    iVar12 = 3;
    do {
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x20) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x24) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x28) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x2c) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x30) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x34) = fVar5;
      *(float *)((int)DAT_803dddac + iVar8 + iVar10 + 0x38) = fVar5;
      iVar10 = iVar10 + 0x1c;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x74) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x75) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x76) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x78) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x79) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x7a) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x80) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x81) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x82) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x88) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x89) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x8a) = 0xff;
    *(float *)((int)DAT_803dddac + iVar8 + 0x90) = fVar2;
    *(float *)((int)DAT_803dddac + iVar8 + 0x94) = fVar4;
    *(float *)((int)DAT_803dddac + iVar8 + 0x98) = fVar2;
    *(float *)((int)DAT_803dddac + iVar8 + 0x9c) = fVar2;
    *(float *)((int)DAT_803dddac + iVar8 + 0xa0) = fVar4;
    *(float *)((int)DAT_803dddac + iVar8 + 0xa4) = fVar2;
    *(byte *)((int)DAT_803dddac + iVar8 + 0xc1) = *(byte *)((int)DAT_803dddac + iVar8 + 0xc1) & 0xbf
    ;
    *(float *)((int)DAT_803dddac + iVar8 + 0xa8) = fVar6;
    *(float *)((int)DAT_803dddac + iVar8 + 0xac) = fVar3;
    *(float *)((int)DAT_803dddac + iVar8 + 0xb0) = fVar6;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x7c) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x7d) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x7e) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x84) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x85) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x86) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x8c) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x8d) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0x8e) = 0xff;
    *(undefined *)((int)DAT_803dddac + iVar8 + 0xc0) = 0x80;
    iVar8 = iVar8 + 0xa4;
    iVar11 = iVar11 + 1;
  } while (iVar11 < 3);
  return;
}

