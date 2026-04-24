// Function: FUN_80140340
// Entry: 80140340
// Size: 2276 bytes

void FUN_80140340(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  ushort *puVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  uint uVar4;
  bool bVar7;
  int *piVar5;
  int iVar6;
  undefined4 *puVar8;
  short sVar9;
  undefined4 *puVar10;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double dVar11;
  undefined8 uVar12;
  int local_48;
  int local_44;
  int local_40 [2];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar12 = FUN_80286838();
  puVar1 = (ushort *)((ulonglong)uVar12 >> 0x20);
  puVar8 = (undefined4 *)uVar12;
  switch(*(undefined *)((int)puVar8 + 10)) {
  case 0:
    FUN_80148ff0();
    uVar3 = FUN_800dbf88((float *)puVar8[10],(undefined *)0x0);
    puVar8[0x1cc] = uVar3;
    uStack_34 = (int)*(short *)puVar8[9] ^ 0x80000000;
    local_38 = 0x43300000;
    dVar11 = (double)FUN_802945e0();
    puVar8[0x1c7] = -(float)((double)FLOAT_803e310c * dVar11 - (double)*(float *)(puVar8[9] + 0x18))
    ;
    puVar8[0x1c8] = *(undefined4 *)(puVar8[9] + 0x1c);
    uStack_2c = (int)*(short *)puVar8[9] ^ 0x80000000;
    local_30 = 0x43300000;
    dVar11 = (double)FUN_80294964();
    puVar8[0x1c9] = -(float)((double)FLOAT_803e310c * dVar11 - (double)*(float *)(puVar8[9] + 0x20))
    ;
    *(undefined *)(puVar8 + 0x1cd) = 0;
    *(undefined *)((int)puVar8 + 10) = 1;
    break;
  case 1:
    FUN_80148ff0();
    FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar1,puVar8,param_11,param_12,param_13,param_14,param_15,param_16);
    iVar6 = FUN_800dbf88((float *)(puVar1 + 0xc),(undefined *)0x0);
    if (puVar8[0x1cc] == iVar6) {
      *(undefined *)((int)puVar8 + 10) = 2;
    }
    break;
  case 2:
    FUN_80148ff0();
    iVar6 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar1,puVar8,param_11,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar6 != 0) {
      FUN_80140c24((int)puVar8);
      break;
    }
    if ((undefined4 *)puVar8[10] != puVar8 + 0x1c7) {
      puVar8[10] = puVar8 + 0x1c7;
      puVar8[0x15] = puVar8[0x15] & 0xfffffbff;
      *(undefined2 *)((int)puVar8 + 0xd2) = 0;
    }
    *(undefined *)((int)puVar8 + 10) = 3;
  case 3:
    FUN_80148ff0();
    iVar6 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar1,puVar8,param_11,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar6 == 0) {
      if (FLOAT_803e306c == (float)puVar8[0xab]) {
        bVar7 = false;
      }
      else if (FLOAT_803e30a0 == (float)puVar8[0xac]) {
        bVar7 = true;
      }
      else if ((float)puVar8[0xad] - (float)puVar8[0xac] <= FLOAT_803e30a4) {
        bVar7 = false;
      }
      else {
        bVar7 = true;
      }
      if (bVar7) {
        FUN_8013a778((double)FLOAT_803e30cc,(int)puVar1,8,0);
        puVar8[0x1e7] = FLOAT_803e30d0;
        puVar8[0x20e] = FLOAT_803e306c;
        FUN_80148ff0();
      }
      else {
        FUN_8013a778((double)FLOAT_803e30d4,(int)puVar1,0,0);
        FUN_80148ff0();
      }
    }
    FUN_80140c24((int)puVar8);
    break;
  case 4:
    FUN_80148ff0();
    iVar6 = FUN_8013b6f0((double)FLOAT_803e310c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,puVar1,puVar8,param_11,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar6 != 0) {
      iVar6 = FUN_800dbf88((float *)puVar8[10],(undefined *)0x0);
      if (puVar8[0x1cc] != iVar6) {
        if (puVar8[10] != puVar8[9] + 0x18) {
          puVar8[10] = puVar8[9] + 0x18;
          puVar8[0x15] = puVar8[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar8 + 0xd2) = 0;
        }
        *(undefined *)((int)puVar8 + 10) = 2;
      }
      break;
    }
    puVar8[0x15] = puVar8[0x15] | 0x10;
    if ((*(char *)*puVar8 == '\0') || (*(char *)(puVar8 + 0x1cd) == '\0')) {
      FUN_8013a778((double)FLOAT_803e307c,(int)puVar1,0x32,0x4000000);
      *(undefined *)((int)puVar8 + 10) = 6;
    }
    else {
      uVar12 = extraout_f1;
      uVar4 = FUN_8002e144();
      if ((uVar4 & 0xff) != 0) {
        puVar8[0x15] = puVar8[0x15] | 0x800;
        iVar6 = 0;
        puVar10 = puVar8;
        do {
          puVar2 = FUN_8002becc(0x24,0x4f0);
          *(undefined *)(puVar2 + 2) = 2;
          *(undefined *)((int)puVar2 + 5) = 1;
          puVar2[0xd] = (short)iVar6;
          uVar3 = FUN_8002e088(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2
                               ,5,*(undefined *)(puVar1 + 0x56),0xffffffff,*(uint **)(puVar1 + 0x18)
                               ,param_14,param_15,param_16);
          puVar10[0x1c0] = uVar3;
          puVar10 = puVar10 + 1;
          iVar6 = iVar6 + 1;
          uVar12 = extraout_f1_00;
        } while (iVar6 < 7);
        FUN_8000bb38((uint)puVar1,0x3db);
        FUN_8000dcdc((uint)puVar1,0x3dc);
      }
      *(char *)*puVar8 = *(char *)*puVar8 + -1;
      FUN_8013a778((double)FLOAT_803e30d4,(int)puVar1,0x34,0x4000000);
      *(undefined *)((int)puVar8 + 10) = 5;
    }
  case 5:
    FUN_80148ff0();
    if (*(float *)(puVar1 + 0x4c) < FLOAT_803e3160) {
      iVar6 = puVar8[0x1cb];
      piVar5 = FUN_80037048(3,local_40);
      for (sVar9 = 0; sVar9 < local_40[0]; sVar9 = sVar9 + 1) {
        if (*piVar5 == iVar6) {
          bVar7 = true;
          goto LAB_801408c0;
        }
        piVar5 = piVar5 + 1;
      }
      bVar7 = false;
LAB_801408c0:
      if (bVar7) {
        iVar6 = FUN_80021884();
        FUN_80139cb8(puVar1,(ushort)iVar6);
      }
    }
    else {
      puVar8[0x15] = puVar8[0x15] & 0xfffff7ff;
      puVar8[0x15] = puVar8[0x15] | 0x1000;
      iVar6 = 0;
      puVar10 = puVar8;
      do {
        FUN_801784f8(puVar10[0x1c0]);
        puVar10 = puVar10 + 1;
        iVar6 = iVar6 + 1;
      } while (iVar6 < 7);
      FUN_8000dbb0();
      iVar6 = *(int *)(puVar1 + 0x5c);
      if ((((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)puVar1[0x50] || ((short)puVar1[0x50] < 0x29)))) &&
         (bVar7 = FUN_8000b598((int)puVar1,0x10), !bVar7)) {
        FUN_800394f0(puVar1,iVar6 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      puVar8[0x15] = puVar8[0x15] & 0xffffffef;
      iVar6 = FUN_80140c24((int)puVar8);
      if (iVar6 == 0) {
        if (puVar8[10] != puVar8[9] + 0x18) {
          puVar8[10] = puVar8[9] + 0x18;
          puVar8[0x15] = puVar8[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar8 + 0xd2) = 0;
        }
        *(undefined *)((int)puVar8 + 10) = 2;
      }
    }
    break;
  case 6:
    FUN_80148ff0();
    if (*(float *)(puVar1 + 0x4c) < FLOAT_803e3160) {
      iVar6 = puVar8[0x1cb];
      piVar5 = FUN_80037048(3,&local_44);
      for (sVar9 = 0; sVar9 < local_44; sVar9 = sVar9 + 1) {
        if (*piVar5 == iVar6) {
          bVar7 = true;
          goto LAB_801409ec;
        }
        piVar5 = piVar5 + 1;
      }
      bVar7 = false;
LAB_801409ec:
      if (bVar7) {
        iVar6 = FUN_80021884();
        FUN_80139cb8(puVar1,(ushort)iVar6);
      }
    }
    else {
      FUN_8013a778((double)FLOAT_803e30d4,(int)puVar1,0x33,0x4000000);
      puVar8[0x1ca] = FLOAT_803e306c;
      iVar6 = *(int *)(puVar1 + 0x5c);
      if (((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)puVar1[0x50] || ((short)puVar1[0x50] < 0x29)) &&
          (bVar7 = FUN_8000b598((int)puVar1,0x10), !bVar7)))) {
        FUN_800394f0(puVar1,iVar6 + 0x3a8,0x299,0x100,0xffffffff,0);
      }
      *(undefined *)((int)puVar8 + 10) = 7;
    }
    break;
  case 7:
    FUN_80148ff0();
    uVar4 = FUN_80022264(0,10);
    if ((((uVar4 == 0) && (iVar6 = *(int *)(puVar1 + 0x5c), (*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0)
         ) && ((0x2f < (short)puVar1[0x50] || ((short)puVar1[0x50] < 0x29)))) &&
       (bVar7 = FUN_8000b598((int)puVar1,0x10), !bVar7)) {
      FUN_800394f0(puVar1,iVar6 + 0x3a8,0x299,0x100,0xffffffff,0);
    }
    puVar8[0x1ca] = (float)puVar8[0x1ca] + FLOAT_803dc074;
    if (((float)puVar8[0x1ca] < FLOAT_803e3168) ||
       (dVar11 = FUN_80021730((float *)puVar8[10],(float *)(puVar1 + 0xc)),
       dVar11 < (double)FLOAT_803e3154)) {
      iVar6 = puVar8[0x1cb];
      piVar5 = FUN_80037048(3,&local_48);
      for (sVar9 = 0; sVar9 < local_48; sVar9 = sVar9 + 1) {
        if (*piVar5 == iVar6) {
          bVar7 = true;
          goto LAB_80140b30;
        }
        piVar5 = piVar5 + 1;
      }
      bVar7 = false;
LAB_80140b30:
      if (bVar7) {
        iVar6 = FUN_80021884();
        FUN_80139cb8(puVar1,(ushort)iVar6);
        break;
      }
    }
    FUN_8013a778((double)FLOAT_803e3084,(int)puVar1,0x32,0x4000000);
    *(undefined *)((int)puVar8 + 10) = 8;
    break;
  case 8:
    FUN_80148ff0();
    if (*(float *)(puVar1 + 0x4c) <= FLOAT_803e30b0) {
      puVar8[0x15] = puVar8[0x15] & 0xffffffef;
      iVar6 = FUN_80140c24((int)puVar8);
      if (iVar6 == 0) {
        if (puVar8[10] != puVar8[9] + 0x18) {
          puVar8[10] = puVar8[9] + 0x18;
          puVar8[0x15] = puVar8[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar8 + 0xd2) = 0;
        }
        *(undefined *)((int)puVar8 + 10) = 2;
      }
    }
  }
  FUN_80286884();
  return;
}

