// Function: FUN_80141c08
// Entry: 80141c08
// Size: 1900 bytes

void FUN_80141c08(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10,int param_11,undefined4 param_12,byte param_13
                 ,uint param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  bool bVar8;
  char cVar9;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar10;
  int iVar11;
  double dVar12;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e3060;
  switch(*(undefined *)((int)param_10 + 10)) {
  case 0:
    param_11 = 2;
    iVar6 = FUN_800db268((float *)param_10[10],0xffffffff,2);
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x1c));
    param_10[0x1c2] = uVar5;
    param_10[0x1c0] = iVar6;
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(iVar6 + 0x20));
    param_10[0x1c1] = uVar5;
    if (*(char *)(param_10[0x1c1] + 3) != '\0') {
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
      param_10[0x1c2] = param_10[0x1c2] ^ param_10[0x1c1];
      param_10[0x1c1] = param_10[0x1c1] ^ param_10[0x1c2];
    }
    if (param_10[10] != param_10[0x1c2] + 8) {
      param_10[10] = param_10[0x1c2] + 8;
      param_10[0x15] = param_10[0x15] & 0xfffffbff;
      *(undefined2 *)((int)param_10 + 0xd2) = 0;
    }
    *(undefined *)((int)param_10 + 10) = 1;
  case 1:
    FUN_80148ff0();
    FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar4 = FUN_800dbf88((float *)(param_9 + 0xc),(undefined *)0x0);
    if (*(byte *)(param_10[0x1c2] + 3) == uVar4) {
      *(undefined *)((int)param_10 + 9) = 1;
      *(undefined *)((int)param_10 + 10) = 2;
    }
    break;
  case 2:
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c0] + 8),'\x01');
    iVar6 = FUN_80139e14();
    if (iVar6 == 0) {
      param_10[0x15] = param_10[0x15] | 0x2010;
      *(undefined *)((int)param_10 + 10) = 3;
    }
    else {
      iVar6 = FUN_800dbf88((float *)(param_9 + 0xc),(undefined *)0x0);
      if (iVar6 == 0) {
        param_10[0x15] = param_10[0x15] | 0x2010;
      }
    }
    break;
  case 3:
    FUN_8013a778((double)FLOAT_803e31a0,(int)param_9,0xe,0x4000000);
    param_10[0xb] = *(float *)(param_10[0x1c1] + 8) - *(float *)(param_10[0x1c0] + 8);
    param_10[0xc] = *(float *)(param_10[0x1c1] + 0x10) - *(float *)(param_10[0x1c0] + 0x10);
    FUN_8000dcdc((uint)param_9,0x13d);
    uStack_1c = FUN_80022264(0x14,0xb4);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    param_10[0x1c3] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
    *(undefined *)((int)param_10 + 10) = 4;
  case 4:
    FUN_80148ff0();
    param_10[0x1c3] = (float)param_10[0x1c3] - FLOAT_803dc074;
    if ((float)param_10[0x1c3] <= FLOAT_803e306c) {
      uStack_1c = FUN_80022264(0x14,0xb4);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      param_10[0x1c3] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
      param_10[0x1c3] = (float)param_10[0x1c3] * FLOAT_803e30b4;
      iVar6 = *(int *)(param_9 + 0x5c);
      if (((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)) &&
          (bVar8 = FUN_8000b598((int)param_9,0x10), !bVar8)))) {
        FUN_800394f0(param_9,iVar6 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar12 = (double)(**(code **)(**(int **)(param_10[9] + 0x68) + 0x20))(param_10[9],param_9);
    *(float *)(param_9 + 6) =
         (float)((double)(float)param_10[0xb] * dVar12 + (double)*(float *)(param_10[0x1c0] + 8));
    *(float *)(param_9 + 10) =
         (float)((double)(float)param_10[0xc] * dVar12 + (double)*(float *)(param_10[0x1c0] + 0x10))
    ;
    fVar1 = *(float *)(*(int *)(param_9 + 0x5c) + 0x2c);
    fVar2 = *(float *)(*(int *)(param_9 + 0x5c) + 0x30);
    if (FLOAT_803e307c < fVar1 * fVar1 + fVar2 * fVar2) {
      iVar6 = FUN_80021884();
      FUN_80139cb8(param_9,(ushort)iVar6);
    }
    cVar9 = (**(code **)(**(int **)(param_10[9] + 0x68) + 0x24))();
    if (cVar9 != '\0') {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(char *)*param_10 = *(char *)*param_10 + -4;
      FUN_8000dbb0();
      *(undefined *)((int)param_10 + 10) = 5;
      uVar4 = FUN_80022264(0,1);
      uVar3 = *(ushort *)((int)local_28 + uVar4 * 2);
      iVar6 = *(int *)(param_9 + 0x5c);
      if ((((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)))) &&
         (bVar8 = FUN_8000b598((int)param_9,0x10), !bVar8)) {
        FUN_800394f0(param_9,iVar6 + 0x3a8,uVar3,0x500,0xffffffff,0);
      }
    }
    break;
  case 5:
    FUN_80021754((float *)(param_9 + 0xc),(float *)(param_10[0x1c1] + 8));
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c1] + 8),'\x01');
    iVar6 = FUN_80139e14();
    if (iVar6 == 0) {
      iVar7 = 0;
      iVar6 = 0;
      iVar11 = 4;
      do {
        iVar10 = *(int *)(param_10[0x1c1] + iVar6 + 0x1c);
        if ((-1 < iVar10) && (iVar10 != *(int *)(param_10[0x1c0] + 0x14))) {
          param_10[0x1c0] = param_10[0x1c1];
          uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))
                            (*(undefined4 *)(param_10[0x1c1] + iVar7 * 4 + 0x1c));
          param_10[0x1c1] = uVar5;
          break;
        }
        iVar6 = iVar6 + 4;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      *(undefined *)((int)param_10 + 10) = 6;
    }
    break;
  case 6:
    FUN_80148ff0();
    FUN_8013d92c((double)FLOAT_803e3118,(short *)param_9,(int)param_10,
                 (float *)(param_10[0x1c1] + 8),'\x01');
    iVar6 = FUN_80139e14();
    if (iVar6 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar8 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar8 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar8 = false;
      }
      else {
        bVar8 = true;
      }
      if (bVar8) {
        FUN_8013a778((double)FLOAT_803e30cc,(int)param_9,8,0);
        param_10[0x1e7] = FLOAT_803e30d0;
        param_10[0x20e] = FLOAT_803e306c;
        FUN_80148ff0();
      }
      else {
        FUN_8013a778((double)FLOAT_803e30d4,(int)param_9,0,0);
        FUN_80148ff0();
      }
      param_10[0x15] = param_10[0x15] & 0xffffdfef;
      *(undefined *)((int)param_10 + 10) = 7;
    }
    break;
  case 7:
    FUN_80148ff0();
    iVar6 = FUN_800dbf88((float *)(param_10[1] + 0x18),(undefined *)0x0);
    iVar7 = FUN_800dbf88((float *)(param_9 + 0xc),(undefined *)0x0);
    if (iVar7 == iVar6) {
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar1 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar1;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
    }
  }
  return;
}

