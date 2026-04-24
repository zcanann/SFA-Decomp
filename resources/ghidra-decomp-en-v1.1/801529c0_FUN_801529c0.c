// Function: FUN_801529c0
// Entry: 801529c0
// Size: 1408 bytes

void FUN_801529c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short *psVar1;
  int iVar2;
  char cVar7;
  short sVar5;
  short sVar6;
  bool bVar8;
  byte bVar9;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  undefined auStack_48 [8];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  uVar14 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar14 >> 0x20);
  puVar10 = (undefined4 *)uVar14;
  iVar12 = *(int *)(psVar1 + 0x26);
  pfVar11 = (float *)*puVar10;
  if ((double)FLOAT_803e34ac < (double)(float)puVar10[0xcb]) {
    if (*(int *)(psVar1 + 100) != 0) {
      FUN_8002cc9c((double)(float)puVar10[0xcb],param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,*(int *)(psVar1 + 100));
      FUN_80037da8((int)psVar1,*(int *)(psVar1 + 100));
      psVar1[100] = 0;
      psVar1[0x65] = 0;
    }
    puVar10[0xcb] = (float)puVar10[0xcb] - FLOAT_803dc074;
    if (FLOAT_803e34ac < (float)puVar10[0xcb]) {
      if ((puVar10[0xb9] & 0x20) == 0) goto LAB_80152f28;
    }
    else {
      puVar10[0xcb] = FLOAT_803e34ac;
      puVar10[0xb9] = puVar10[0xb9] | 0x20;
      FUN_8000b7dc((int)psVar1,4);
      FUN_8014d504((double)FLOAT_803e34b8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)psVar1,(int)puVar10,0,0,0,in_r8,in_r9,in_r10);
    }
  }
  if ((puVar10[0xb7] & 0x2000) == 0) {
    if (FLOAT_803e34c8 <= *(float *)(psVar1 + 8) - *(float *)(iVar12 + 0xc)) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_8000b5f0((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_8000bb38((uint)psVar1,0x18d);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
    *psVar1 = *psVar1 + (short)*(char *)(iVar12 + 0x2a);
  }
  else {
    iVar2 = FUN_80010340((double)(float)puVar10[0xbf],pfVar11);
    if ((((iVar2 != 0) || (pfVar11[4] != 0.0)) &&
        (cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar11), cVar7 != '\0')) &&
       (cVar7 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e34bc,*puVar10,psVar1,&DAT_803dc910,0xffffffff),
       cVar7 != '\0')) {
      puVar10[0xb7] = puVar10[0xb7] & 0xffffdfff;
    }
    *(float *)(psVar1 + 0x12) = (pfVar11[0x1a] - *(float *)(psVar1 + 6)) / FLOAT_803dc074;
    *(float *)(psVar1 + 0x16) = (pfVar11[0x1c] - *(float *)(psVar1 + 10)) / FLOAT_803dc074;
    iVar2 = (int)*(char *)(iVar12 + 0x2a);
    if (iVar2 == 0) {
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3f4(psVar1,puVar10,0xf,0);
    }
    else if ((puVar10[0xb7] & 0x2000) == 0) {
      local_28 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        iVar2 = -iVar2;
      }
      *psVar1 = *psVar1 + (short)iVar2;
    }
    else {
      sVar6 = (short)(iVar2 << 8);
      local_30 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      sVar5 = sVar6;
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        sVar5 = -sVar6;
      }
      *psVar1 = *psVar1 - sVar5;
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3f4(psVar1,puVar10,0xf,0);
      local_28 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        sVar6 = -sVar6;
      }
      *psVar1 = *psVar1 + sVar6;
    }
    if (FLOAT_803e34c4 <= *(float *)(psVar1 + 8) - pfVar11[0x1b]) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_8000b5f0((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_8000bb38((uint)psVar1,0x18d);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
  }
  if (*(char *)((int)puVar10 + 0x33a) != '\0') {
    param_2 = (double)FLOAT_803dc918;
    *(float *)(psVar1 + 0x14) =
         (float)(param_2 * (double)FLOAT_803dc074 + (double)*(float *)(psVar1 + 0x14));
  }
  if ((psVar1[0x58] & 0x800U) != 0) {
    local_3c = FLOAT_803e34ac;
    local_38 = FLOAT_803e34ac;
    local_34 = FLOAT_803e34ac;
    local_40 = FLOAT_803e34b8;
    param_2 = (double)FLOAT_803e34d0;
    FUN_80098608((double)FLOAT_803e34cc,param_2);
    local_38 = FLOAT_803e34d4;
    FUN_8009742c((double)FLOAT_803e34d8,psVar1,1,6,0x20,(int)auStack_48);
    local_3c = FLOAT_803e34ac;
    local_38 = FLOAT_803e34dc;
    local_34 = FLOAT_803e34dc;
  }
  if (FLOAT_803e34e0 <= *(float *)(psVar1 + 0x14)) {
    if (FLOAT_803e34cc < *(float *)(psVar1 + 0x14)) {
      *(float *)(psVar1 + 0x14) = FLOAT_803e34cc;
    }
  }
  else {
    *(float *)(psVar1 + 0x14) = FLOAT_803e34e0;
  }
  dVar13 = (double)FLOAT_803e34ac;
  if (dVar13 == (double)(float)puVar10[0xcb]) {
    if (((*(char *)(iVar12 + 0x2e) != -1) && (*(int *)(psVar1 + 100) != 0)) &&
       (bVar9 = FUN_801a06f0(*(int *)(psVar1 + 100)), bVar9 != 0)) {
      iVar2 = FUN_8002bac4();
      FUN_80036548(iVar2,(int)psVar1,'\x16',2,0);
      FUN_8015281c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)psVar1,0x3b2)
      ;
      FUN_8000bb38((uint)psVar1,0xe9);
      puVar10[0xcb] = FLOAT_803dc91c;
    }
    dVar13 = (double)FLOAT_803e34e4;
    local_28 = (longlong)(int)(dVar13 * (double)FLOAT_803dc078);
    uVar3 = FUN_80022264(0,(int)(dVar13 * (double)FLOAT_803dc078));
    if (uVar3 == 0) {
      dVar13 = (double)FUN_8000bb38((uint)psVar1,0xe7);
    }
    if (*(int *)(psVar1 + 100) == 0) {
      cVar7 = *(char *)(iVar12 + 0x2a);
      iVar2 = FUN_8015281c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)psVar1,0x639);
      uVar4 = 0;
      if ((*(char *)(iVar12 + 0x2a) != '\0') && ((puVar10[0xb7] & 0x2000) == 0)) {
        uVar4 = 1;
      }
      *(undefined4 *)(iVar2 + 0xf4) = uVar4;
      FUN_80037e24((int)psVar1,iVar2,(ushort)(cVar7 != '\0'));
    }
    else {
      iVar12 = FUN_800395a4(*(int *)(psVar1 + 100),0);
      if (iVar12 != 0) {
        iVar2 = *(short *)(iVar12 + 8) + -0x3c;
        if (iVar2 < 0) {
          iVar2 = *(short *)(iVar12 + 8) + 0x26d4;
        }
        *(short *)(iVar12 + 8) = (short)iVar2;
      }
    }
  }
LAB_80152f28:
  FUN_8028688c();
  return;
}

