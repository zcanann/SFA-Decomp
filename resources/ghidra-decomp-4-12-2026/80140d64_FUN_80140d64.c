// Function: FUN_80140d64
// Entry: 80140d64
// Size: 2224 bytes

void FUN_80140d64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  ushort uVar3;
  ushort *puVar4;
  uint uVar5;
  undefined2 *puVar6;
  undefined4 uVar7;
  bool bVar9;
  int iVar8;
  undefined4 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  double dVar13;
  double extraout_f1;
  double extraout_f1_00;
  undefined8 uVar14;
  
  uVar14 = FUN_8028683c();
  puVar4 = (ushort *)((ulonglong)uVar14 >> 0x20);
  puVar10 = (undefined4 *)uVar14;
  switch(*(undefined *)((int)puVar10 + 10)) {
  case 0:
    FUN_80148ff0();
    iVar11 = 4;
    iVar8 = FUN_800db268((float *)(puVar10[9] + 0x18),0xffffffff,4);
    puVar10[0x1c7] = iVar8;
    iVar8 = puVar10[0x1c7];
    if (*(char *)(iVar8 + 3) == '\0') {
      uVar7 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar8 + 0x1c));
      puVar10[0x1c8] = uVar7;
      if (puVar10[10] != puVar10[0x1c8] + 8) {
        puVar10[10] = puVar10[0x1c8] + 8;
        puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)puVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)puVar10 + 10) = 3;
    }
    else {
      if (puVar10[10] != iVar8 + 8) {
        puVar10[10] = iVar8 + 8;
        puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)puVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)puVar10 + 10) = 1;
    }
    FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,iVar11,param_12,param_13,param_14,param_15,param_16);
    break;
  case 1:
    FUN_80148ff0();
    iVar8 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar8 == 0) {
      puVar10[0x15] = puVar10[0x15] | 0x10;
      *(undefined *)((int)puVar10 + 10) = 2;
    }
    else if (iVar8 == 2) {
      *(undefined *)(puVar10 + 2) = 1;
      *(undefined *)((int)puVar10 + 10) = 0;
      fVar1 = FLOAT_803e306c;
      puVar10[0x1c7] = FLOAT_803e306c;
      puVar10[0x1c8] = fVar1;
      puVar10[0x15] = puVar10[0x15] & 0xffffffef;
      puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
      *(undefined *)((int)puVar10 + 0xd) = 0xff;
    }
    break;
  case 2:
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e30a8,(short *)puVar4,(int)puVar10,(float *)(puVar10[9] + 0x18),
                 '\x01');
    iVar8 = FUN_80139e14();
    if (iVar8 == 0) {
      FUN_8013a778((double)FLOAT_803e3074,(int)puVar4,0x1a,0x4000000);
      *(undefined *)((int)puVar10 + 10) = 6;
      *(char *)*puVar10 = *(char *)*puVar10 + -4;
    }
    break;
  case 3:
    FUN_80148ff0();
    FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar4,puVar10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar5 = FUN_800dbf88((float *)(puVar4 + 0xc),(undefined *)0x0);
    if (*(byte *)(puVar10[0x1c8] + 3) == uVar5) {
      *(undefined *)((int)puVar10 + 9) = 1;
      *(undefined *)((int)puVar10 + 10) = 4;
    }
    break;
  case 4:
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
                 '\x01');
    FUN_80139e14();
    iVar8 = FUN_800dbf88((float *)(puVar4 + 0xc),(undefined *)0x0);
    if (iVar8 == 0) {
      puVar10[0x15] = puVar10[0x15] | 0x10;
      *(undefined *)((int)puVar10 + 10) = 5;
    }
    break;
  case 5:
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c7] + 8),
                 '\x01');
    iVar8 = FUN_80139e14();
    if (iVar8 != 0) break;
    FUN_8013a778((double)FLOAT_803e3074,(int)puVar4,0x1a,0x4000000);
    *(undefined *)((int)puVar10 + 10) = 7;
    *(char *)*puVar10 = *(char *)*puVar10 + -4;
  case 7:
    FUN_80148ff0();
    uVar3 = (ushort)((int)*(char *)(puVar10[0x1c7] + 0x2c) << 8);
    sVar2 = uVar3 - *puVar4;
    if (0x8000 < sVar2) {
      sVar2 = sVar2 + 1;
    }
    if (sVar2 < -0x8000) {
      sVar2 = sVar2 + -1;
    }
    iVar8 = (int)sVar2;
    if (iVar8 < 0) {
      iVar8 = -iVar8;
    }
    if (0x3fff < iVar8) {
      uVar3 = uVar3 + 0x8000;
    }
    FUN_80139cb8(puVar4,uVar3);
    dVar13 = (double)*(float *)(puVar4 + 0x4c);
    if (dVar13 <= (double)FLOAT_803e313c) {
LAB_801411bc:
      bVar9 = true;
    }
    else {
      if ((puVar10[0x15] & 0x800) == 0) {
        uVar5 = FUN_8002e144();
        if ((uVar5 & 0xff) != 0) {
          puVar10[0x15] = puVar10[0x15] | 0x800;
          iVar8 = 0;
          puVar12 = puVar10;
          do {
            puVar6 = FUN_8002becc(0x24,0x4f0);
            *(undefined *)(puVar6 + 2) = 2;
            *(undefined *)((int)puVar6 + 5) = 1;
            puVar6[0xd] = (short)iVar8;
            uVar7 = FUN_8002e088(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 puVar6,5,*(undefined *)(puVar4 + 0x56),0xffffffff,
                                 *(uint **)(puVar4 + 0x18),param_14,param_15,param_16);
            puVar12[0x1c0] = uVar7;
            puVar12 = puVar12 + 1;
            iVar8 = iVar8 + 1;
            dVar13 = extraout_f1;
          } while (iVar8 < 7);
          FUN_8000bb38((uint)puVar4,0x3db);
          FUN_8000dcdc((uint)puVar4,0x3dc);
        }
        goto LAB_801411bc;
      }
      if ((((code *)puVar10[0x1c9] != (code *)0x0) &&
          (iVar8 = (*(code *)puVar10[0x1c9])(puVar10[9],1), iVar8 == 0)) ||
         (*(float *)(puVar4 + 0x4c) <= FLOAT_803e3194)) goto LAB_801411bc;
      puVar10[0x15] = puVar10[0x15] & 0xfffff7ff;
      puVar10[0x15] = puVar10[0x15] | 0x1000;
      iVar8 = 0;
      puVar12 = puVar10;
      do {
        FUN_801784f8(puVar12[0x1c0]);
        puVar12 = puVar12 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 7);
      FUN_8000dbb0();
      iVar8 = *(int *)(puVar4 + 0x5c);
      if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)) &&
          (bVar9 = FUN_8000b598((int)puVar4,0x10), !bVar9)))) {
        FUN_800394f0(puVar4,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar9 = false;
    }
    if (!bVar9) {
      *(undefined *)((int)puVar10 + 10) = 8;
      puVar10[0x1ca] = FLOAT_803e3188;
    }
    break;
  case 6:
    FUN_80148ff0();
    dVar13 = (double)*(float *)(puVar4 + 0x4c);
    if (dVar13 <= (double)FLOAT_803e313c) {
LAB_8014149c:
      bVar9 = true;
    }
    else {
      if ((puVar10[0x15] & 0x800) == 0) {
        uVar5 = FUN_8002e144();
        if ((uVar5 & 0xff) != 0) {
          puVar10[0x15] = puVar10[0x15] | 0x800;
          iVar8 = 0;
          puVar12 = puVar10;
          do {
            puVar6 = FUN_8002becc(0x24,0x4f0);
            *(undefined *)(puVar6 + 2) = 2;
            *(undefined *)((int)puVar6 + 5) = 1;
            puVar6[0xd] = (short)iVar8;
            uVar7 = FUN_8002e088(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 puVar6,5,*(undefined *)(puVar4 + 0x56),0xffffffff,
                                 *(uint **)(puVar4 + 0x18),param_14,param_15,param_16);
            puVar12[0x1c0] = uVar7;
            puVar12 = puVar12 + 1;
            iVar8 = iVar8 + 1;
            dVar13 = extraout_f1_00;
          } while (iVar8 < 7);
          FUN_8000bb38((uint)puVar4,0x3db);
          FUN_8000dcdc((uint)puVar4,0x3dc);
        }
        goto LAB_8014149c;
      }
      if ((((code *)puVar10[0x1c9] != (code *)0x0) &&
          (iVar8 = (*(code *)puVar10[0x1c9])(puVar10[9],1), iVar8 == 0)) ||
         (*(float *)(puVar4 + 0x4c) <= FLOAT_803e3194)) goto LAB_8014149c;
      puVar10[0x15] = puVar10[0x15] & 0xfffff7ff;
      puVar10[0x15] = puVar10[0x15] | 0x1000;
      iVar8 = 0;
      puVar12 = puVar10;
      do {
        FUN_801784f8(puVar12[0x1c0]);
        puVar12 = puVar12 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 7);
      FUN_8000dbb0();
      iVar8 = *(int *)(puVar4 + 0x5c);
      if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)))) &&
         (bVar9 = FUN_8000b598((int)puVar4,0x10), !bVar9)) {
        FUN_800394f0(puVar4,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar9 = false;
    }
    if (!bVar9) {
      *(undefined *)(puVar10 + 2) = 1;
      *(undefined *)((int)puVar10 + 10) = 0;
      fVar1 = FLOAT_803e306c;
      puVar10[0x1c7] = FLOAT_803e306c;
      puVar10[0x1c8] = fVar1;
      puVar10[0x15] = puVar10[0x15] & 0xffffffef;
      puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
      puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
      *(undefined *)((int)puVar10 + 0xd) = 0xff;
    }
    break;
  case 8:
    FUN_80148ff0();
    puVar10[0x1ca] = (float)puVar10[0x1ca] - FLOAT_803dc074;
    if ((float)puVar10[0x1ca] <= FLOAT_803e306c) {
      FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar4,(int)puVar10,(float *)(puVar10[0x1c8] + 8)
                   ,'\x01');
      FUN_80139e14();
      iVar8 = FUN_800dbf88((float *)(puVar4 + 0xc),(undefined *)0x0);
      if (iVar8 != 0) {
        *(undefined *)(puVar10 + 2) = 1;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        puVar10[0x1c7] = FLOAT_803e306c;
        puVar10[0x1c8] = fVar1;
        puVar10[0x15] = puVar10[0x15] & 0xffffffef;
        puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
        *(undefined *)((int)puVar10 + 0xd) = 0xff;
      }
    }
  }
  FUN_80286888();
  return;
}

