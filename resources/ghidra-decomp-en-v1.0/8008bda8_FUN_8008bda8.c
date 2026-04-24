// Function: FUN_8008bda8
// Entry: 8008bda8
// Size: 1120 bytes

void FUN_8008bda8(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  if (DAT_803dd12c != (int *)0x0) {
    if (DAT_803dd12c != (int *)0x0) {
      if (*DAT_803dd12c != 0) {
        FUN_80054308();
      }
      if (DAT_803dd12c[1] != 0) {
        FUN_80054308();
      }
      FUN_80023800(DAT_803dd12c[2]);
      FUN_80023800(DAT_803dd12c[4]);
      FUN_80023800(DAT_803dd12c);
    }
    DAT_803dd12c = (int *)0x0;
  }
  DAT_803dd12c = (int *)FUN_80023cc8(600,0x17,0);
  FUN_800033a8(DAT_803dd12c,0,600);
  *(undefined *)(DAT_803dd12c + 0x94) = 0xff;
  iVar6 = FUN_800221a0(0,0x1c);
  DAT_803dd12c[0x86] = iVar6;
  *(undefined *)((int)DAT_803dd12c + 0x252) = 0xc;
  *(undefined *)((int)DAT_803dd12c + 0x253) = 0;
  DAT_803dd12c[0x83] = (int)FLOAT_803df0f4;
  DAT_803dd12c[0x84] = 0xb4;
  DAT_803dd12c[7] = (int)FLOAT_803df0f8;
  DAT_803dd12c[0x85] =
       (int)((float)((double)CONCAT44(0x43300000,DAT_803dd12c[0x84] ^ 0x80000000) - DOUBLE_803df090)
            / FLOAT_803df060);
  DAT_803dd12c[0x87] = 0xc38;
  DAT_803dd12c[0x88] = 0xc38;
  DAT_803dd12c[0x89] = 0xc38;
  DAT_803dd12c[0x8a] = 0xc38;
  DAT_803dd12c[0x8b] = 0xc38;
  DAT_803dd12c[0x8c] = 0xc38;
  DAT_803dd12c[0x8d] = 0xc38;
  DAT_803dd12c[0x8e] = 0xc38;
  iVar6 = FUN_80054d54(DAT_803dd12c[0x87]);
  *DAT_803dd12c = iVar6;
  iVar6 = FUN_80054d54(DAT_803dd12c[0x88]);
  DAT_803dd12c[1] = iVar6;
  DAT_803dd12c[5] = 0xc38;
  DAT_803dd12c[6] = 0xc38;
  iVar8 = *DAT_803dd12c;
  iVar6 = FUN_80054c98(*(undefined2 *)(iVar8 + 10),*(undefined2 *)(iVar8 + 0xc),6,0,0,1,0,1,1);
  DAT_803dd12c[2] = iVar6;
  iVar6 = FUN_80054c98(*(undefined2 *)(iVar8 + 10),*(undefined2 *)(iVar8 + 0xc),6,0,0,1,0,1,1);
  DAT_803dd12c[4] = iVar6;
  fVar5 = FLOAT_803df100;
  fVar4 = FLOAT_803df0fc;
  fVar3 = FLOAT_803df06c;
  fVar2 = FLOAT_803df05c;
  fVar1 = FLOAT_803df058;
  iVar8 = 0;
  iVar6 = 0;
  do {
    iVar7 = 0;
    iVar9 = 3;
    do {
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x20) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x24) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x28) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x2c) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x30) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x34) = fVar4;
      *(float *)((int)DAT_803dd12c + iVar6 + iVar7 + 0x38) = fVar4;
      iVar7 = iVar7 + 0x1c;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x74) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x75) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x76) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x78) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x79) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x7a) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x80) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x81) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x82) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x88) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x89) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x8a) = 0xff;
    *(float *)((int)DAT_803dd12c + iVar6 + 0x90) = fVar1;
    *(float *)((int)DAT_803dd12c + iVar6 + 0x94) = fVar3;
    *(float *)((int)DAT_803dd12c + iVar6 + 0x98) = fVar1;
    *(float *)((int)DAT_803dd12c + iVar6 + 0x9c) = fVar1;
    *(float *)((int)DAT_803dd12c + iVar6 + 0xa0) = fVar3;
    *(float *)((int)DAT_803dd12c + iVar6 + 0xa4) = fVar1;
    *(byte *)((int)DAT_803dd12c + iVar6 + 0xc1) = *(byte *)((int)DAT_803dd12c + iVar6 + 0xc1) & 0xbf
    ;
    *(float *)((int)DAT_803dd12c + iVar6 + 0xa8) = fVar5;
    *(float *)((int)DAT_803dd12c + iVar6 + 0xac) = fVar2;
    *(float *)((int)DAT_803dd12c + iVar6 + 0xb0) = fVar5;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x7c) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x7d) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x7e) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x84) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x85) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x86) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x8c) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x8d) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0x8e) = 0xff;
    *(undefined *)((int)DAT_803dd12c + iVar6 + 0xc0) = 0x80;
    iVar6 = iVar6 + 0xa4;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 3);
  return;
}

