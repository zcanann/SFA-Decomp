// Function: FUN_80159e04
// Entry: 80159e04
// Size: 1652 bytes

/* WARNING: Removing unreachable block (ram,0x8015a454) */
/* WARNING: Removing unreachable block (ram,0x80159e14) */

void FUN_80159e04(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,double param_7,undefined8 param_8,ushort *param_9,
                 undefined4 *param_10)

{
  float fVar1;
  short sVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  char cVar7;
  uint uVar6;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  float *pfVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined auStack_5c [6];
  undefined2 local_56;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  longlong local_28;
  
  fVar1 = FLOAT_803e38c8;
  pfVar8 = (float *)*param_10;
  dVar10 = (double)(float)param_10[0xcc];
  dVar9 = (double)FLOAT_803e38c8;
  if ((dVar10 != dVar9) &&
     (param_10[0xcc] = (float)(dVar10 - (double)FLOAT_803dc074),
     (double)(float)param_10[0xcc] <= dVar9)) {
    param_10[0xcc] = fVar1;
  }
  param_10[0xba] = param_10[0xba] | 0x100;
  local_50 = FLOAT_803e38c8;
  local_4c = FLOAT_803e38cc;
  local_48 = FLOAT_803e38c8;
  local_54 = FLOAT_803e38bc;
  local_56 = 0x605;
  if ((param_9[0x58] & 0x800) != 0) {
    in_r8 = 0;
    in_r9 = *DAT_803dd708;
    (**(code **)(in_r9 + 8))(param_9,1999,auStack_5c,2,0xffffffff);
    piVar4 = (int *)param_10[0xda];
    if (piVar4 != (int *)0x0) {
      dVar10 = (double)*(float *)(param_9 + 8);
      param_3 = (double)*(float *)(param_9 + 10);
      FUN_8001de4c((double)*(float *)(param_9 + 6),dVar10,param_3,piVar4);
    }
    else {
      if (piVar4 == (int *)0x0) {
        piVar4 = FUN_8001f58c(0,'\x01');
        param_10[0xda] = piVar4;
      }
      if (param_10[0xda] != 0) {
        FUN_8001dbf0(param_10[0xda],2);
        param_3 = (double)*(float *)(param_9 + 10);
        FUN_8001de4c((double)*(float *)(param_9 + 6),(double)*(float *)(param_9 + 8),param_3,
                     (int *)param_10[0xda]);
        FUN_8001dbb4(param_10[0xda],0xc0,0x40,0xff,0xff);
        FUN_8001dadc(param_10[0xda],0xc0,0x40,0xff,0xff);
        dVar10 = (double)FLOAT_803e38ac;
        FUN_8001dcfc((double)FLOAT_803e38a8,dVar10,param_10[0xda]);
        FUN_8001dc18(param_10[0xda],1);
        FUN_8001dc30((double)FLOAT_803e38b0,param_10[0xda],'\x01');
        FUN_8001d6e4(param_10[0xda],0,0);
        FUN_8001de04(param_10[0xda],0);
      }
    }
  }
  if ((param_10[0xb7] & 0x80000000) != 0) {
    *(undefined *)((int)param_10 + 0x33a) =
         (&DAT_803207ca)[(uint)*(byte *)((int)param_10 + 0x33a) * 0xc];
    param_10[0xca] = FLOAT_803e38d0;
    FUN_8000b844((int)param_9,1000);
  }
  if ((param_10[0xb7] & 0x2000) != 0) {
    dVar9 = FUN_80293900((double)((pfVar8[0x1c] - *(float *)(param_9 + 0x10)) *
                                  (pfVar8[0x1c] - *(float *)(param_9 + 0x10)) +
                                 (pfVar8[0x1a] - *(float *)(param_9 + 0xc)) *
                                 (pfVar8[0x1a] - *(float *)(param_9 + 0xc)) +
                                 (pfVar8[0x1b] - *(float *)(param_9 + 0xe)) *
                                 (pfVar8[0x1b] - *(float *)(param_9 + 0xe))));
    param_10[0xcb] = (float)dVar9;
    if (((float)param_10[0xcb] < FLOAT_803e38a8) && ((float)param_10[0xcc] == FLOAT_803e38c8)) {
      param_10[0xb9] = param_10[0xb9] & 0xfffeffff;
    }
    fVar1 = FLOAT_803e38d4 - (float)param_10[0xcb] / FLOAT_803e38d8;
    fVar3 = FLOAT_803e38c8;
    if ((FLOAT_803e38c8 <= fVar1) && (fVar3 = fVar1, FLOAT_803e38d4 < fVar1)) {
      fVar3 = FLOAT_803e38d4;
    }
    iVar5 = FUN_80010340((double)((float)param_10[0xbf] * fVar3),pfVar8);
    if ((((iVar5 != 0) || (pfVar8[4] != 0.0)) &&
        (cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar8), cVar7 != '\0')) &&
       (cVar7 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e38dc,*param_10,param_9,&DAT_803dc960,0xffffffff),
       cVar7 != '\0')) {
      param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
    }
    dVar10 = (double)pfVar8[0x1b];
    param_3 = (double)pfVar8[0x1c];
    param_4 = (double)FLOAT_803e38e0;
    param_5 = (double)FLOAT_803e38e4;
    param_6 = (double)FLOAT_803e38e8;
    param_7 = (double)(float)param_10[0xc1];
    FUN_8014cd98((double)pfVar8[0x1a],dVar10,param_3,param_4,param_5,param_6,param_7,(int)param_9);
  }
  if ((param_10[0xb7] & 0x40000000) != 0) {
    iVar5 = (uint)*(byte *)((int)param_10 + 0x33a) * 0xc;
    FUN_8014d504((double)*(float *)(&DAT_803207c0 + iVar5),dVar10,param_3,param_4,param_5,param_6,
                 param_7,param_8,(int)param_9,(int)param_10,(uint)(byte)(&DAT_803207c8)[iVar5],0,0,
                 in_r8,in_r9,in_r10);
    *(undefined *)((int)param_10 + 0x33a) =
         (&DAT_803207c9)[(uint)*(byte *)((int)param_10 + 0x33a) * 0xc];
  }
  if ((float)param_10[0xc9] <= FLOAT_803e38c8) {
    param_10[0xc9] = FLOAT_803e38c8;
    dVar10 = (double)FLOAT_803e38d4;
    dVar11 = (double)(float)(dVar10 - (double)(((float)param_10[0xca] - FLOAT_803e38f0) /
                                              FLOAT_803e38f4));
    dVar9 = (double)FLOAT_803e38f8;
    if ((dVar9 <= dVar11) && (dVar9 = dVar11, dVar10 < dVar11)) {
      dVar9 = dVar10;
    }
    if ((float)param_10[0xca] <= FLOAT_803e38f0) {
      param_10[0xca] = FLOAT_803e38f0;
    }
    else {
      param_10[0xca] = (float)param_10[0xca] - FLOAT_803dc074;
    }
    dVar10 = FUN_80293900((double)(*(float *)(param_9 + 0x12) * *(float *)(param_9 + 0x12) +
                                  *(float *)(param_9 + 0x16) * *(float *)(param_9 + 0x16)));
    fVar1 = (float)(dVar10 / (double)FLOAT_803e38e0);
    fVar3 = FLOAT_803e38c8;
    if ((FLOAT_803e38c8 <= fVar1) && (fVar3 = fVar1, FLOAT_803e38d4 < fVar1)) {
      fVar3 = FLOAT_803e38d4;
    }
    local_38 = (double)CONCAT44(0x43300000,(int)(short)param_9[1] ^ 0x80000000);
    iVar5 = (int)((float)(local_38 - DOUBLE_803e38c0) -
                 fVar3 * (float)((double)FLOAT_803e38fc * dVar9) * FLOAT_803dc074);
    local_40 = (double)(longlong)iVar5;
    param_9[1] = (ushort)iVar5;
    local_30 = (double)(longlong)(int)(float)param_10[0xca];
    FUN_8014d194((double)(float)((double)FLOAT_803e3900 * dVar9),(double)FLOAT_803e38c8,param_9,
                 (int)param_10,(int)(float)param_10[0xca],'\x01');
  }
  else {
    param_10[0xc9] = -(FLOAT_803e38ec * FLOAT_803dc074 - (float)param_10[0xc9]);
    local_40 = (double)CONCAT44(0x43300000,(int)(short)*param_9 ^ 0x80000000);
    iVar5 = (int)((float)param_10[0xc9] * FLOAT_803dc074 + (float)(local_40 - DOUBLE_803e38c0));
    local_38 = (double)(longlong)iVar5;
    *param_9 = (ushort)iVar5;
  }
  dVar9 = (double)FUN_802932a4((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
  local_30 = (double)CONCAT44(0x43300000,(int)(short)param_9[1] ^ 0x80000000);
  iVar5 = (int)((double)(float)(local_30 - DOUBLE_803e38c0) * dVar9);
  local_38 = (double)(longlong)iVar5;
  param_9[1] = (ushort)iVar5;
  dVar9 = (double)FUN_802932a4((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
  local_40 = (double)CONCAT44(0x43300000,(int)(short)param_9[2] ^ 0x80000000);
  iVar5 = (int)((double)(float)(local_40 - DOUBLE_803e38c0) * dVar9);
  local_28 = (longlong)iVar5;
  param_9[2] = (ushort)iVar5;
  uVar6 = FUN_80022264(0,0x2ee);
  if (uVar6 == 0) {
    FUN_8000bb38((uint)param_9,0x3e9);
  }
  if ((float)param_10[0xc9] <= FLOAT_803e38c8) {
    FUN_8000b844((int)param_9,1000);
  }
  else {
    FUN_8000bb38((uint)param_9,1000);
    iVar5 = (int)((FLOAT_803e3904 * (float)param_10[0xc9]) / FLOAT_803e3908);
    local_28 = (longlong)iVar5;
    FUN_8000b9bc((double)((float)param_10[0xc9] / FLOAT_803e3908),(int)param_9,1000,(byte)iVar5);
  }
  if ((param_10[0xd0] != 0) &&
     ((sVar2 = *(short *)(param_10[0xd0] + 0x46), sVar2 == 0x1f || (sVar2 == 0)))) {
    FUN_8000bb38((uint)param_9,0x23d);
  }
  return;
}

