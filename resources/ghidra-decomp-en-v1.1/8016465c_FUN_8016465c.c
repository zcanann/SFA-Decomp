// Function: FUN_8016465c
// Entry: 8016465c
// Size: 1936 bytes

/* WARNING: Removing unreachable block (ram,0x80164dc8) */
/* WARNING: Removing unreachable block (ram,0x80164dc0) */
/* WARNING: Removing unreachable block (ram,0x80164db8) */
/* WARNING: Removing unreachable block (ram,0x80164db0) */
/* WARNING: Removing unreachable block (ram,0x80164684) */
/* WARNING: Removing unreachable block (ram,0x8016467c) */
/* WARNING: Removing unreachable block (ram,0x80164674) */
/* WARNING: Removing unreachable block (ram,0x8016466c) */

void FUN_8016465c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  float *pfVar5;
  uint uVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  uint local_88;
  int local_84;
  uint uStack_80;
  int iStack_7c;
  longlong local_78;
  undefined8 local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined8 local_60;
  
  fVar2 = FLOAT_803e3c58;
  iVar7 = *(int *)(param_9 + 0x5c);
  cVar1 = *(char *)(iVar7 + 0x278);
  if (cVar1 == '\0') {
    if (*(float *)(iVar7 + 0x26c) <= *(float *)(param_9 + 4)) {
      *(undefined *)(iVar7 + 0x278) = 1;
    }
    else {
      *(float *)(param_9 + 4) = *(float *)(iVar7 + 0x270) * FLOAT_803dc074 + *(float *)(param_9 + 4)
      ;
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = FUN_80036974((int)param_9,&local_84,&iStack_7c,&uStack_80);
    if (iVar4 != 0) {
      FUN_80036018((int)param_9);
      *(undefined *)(iVar7 + 0x278) = 2;
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
      if (param_9[0x23] == 0x4c1) {
        *(float *)(iVar7 + 0x2a0) = FLOAT_803e3c34;
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = FUN_8002bac4();
    dVar13 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
    dVar12 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
    dVar11 = (double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12));
    iVar4 = FUN_8002ba84();
    if ((iVar4 != 0) && (*(short *)(iVar4 + 0x46) == 0x24)) {
      if (dVar11 < (double)FLOAT_803e3c38) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,param_9,0,1);
      }
      dVar10 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
      dVar9 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
      dVar8 = (double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9));
      if (dVar8 < dVar11) {
        dVar11 = dVar8;
        dVar12 = dVar9;
        dVar13 = dVar10;
      }
    }
    dVar11 = FUN_80293900(dVar11);
    local_78 = (longlong)(int)dVar11;
    *(short *)(iVar7 + 0x268) = (short)(int)dVar11;
    dVar10 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar7 + 0x288));
    dVar9 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar7 + 0x28c));
    dVar8 = FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
    local_70 = (double)(longlong)(int)dVar8;
    *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xf7;
    fVar3 = FLOAT_803e3c40;
    fVar2 = FLOAT_803e3c3c;
    dVar11 = DOUBLE_803e3c28;
    uStack_64 = (uint)*(ushort *)(iVar7 + 0x268);
    if ((FLOAT_803e3c3c <= (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3c28)) ||
       (uStack_64 == 0)) {
      uVar6 = (int)dVar8 & 0xffff;
      local_60 = (double)CONCAT44(0x43300000,uVar6);
      if ((FLOAT_803e3bf4 < (float)(local_60 - DOUBLE_803e3c28)) && (uVar6 != 0)) {
        local_60 = (double)CONCAT44(0x43300000,uVar6);
        dVar11 = (double)(FLOAT_803e3bf4 * (float)(local_60 - DOUBLE_803e3c28));
        *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) - (float)(dVar10 / dVar11);
        *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) - (float)(dVar9 / dVar11);
      }
    }
    else {
      *(float *)(param_9 + 0x12) =
           *(float *)(param_9 + 0x12) -
           (float)(dVar13 / (double)(FLOAT_803e3c40 *
                                    ((float)((double)CONCAT44(0x43300000,uStack_64) -
                                            DOUBLE_803e3c28) - FLOAT_803e3c3c)));
      local_70 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar7 + 0x268));
      *(float *)(param_9 + 0x16) =
           *(float *)(param_9 + 0x16) -
           (float)(dVar12 / (double)(fVar3 * ((float)(local_70 - dVar11) - fVar2)));
      fVar2 = FLOAT_803e3c44;
      local_78 = (longlong)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      *(short *)(iVar7 + 0x27c) = (short)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      local_60 = (double)(longlong)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(short *)(iVar7 + 0x27e) = (short)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 8;
    }
    local_68 = 0x43300000;
    FUN_80164068(param_9,iVar7);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar7);
    *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803dc074;
    if (FLOAT_803e3c00 <= *(float *)(iVar7 + 0x2a0)) {
      iVar4 = FUN_80036974((int)param_9,&local_84,&iStack_7c,&uStack_80);
      if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != param_9[0x23])) {
        if (param_9[0x23] == 0x4ba) {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xef;
          *(undefined *)(iVar7 + 0x278) = 3;
          *(float *)(iVar7 + 0x270) = FLOAT_803e3c48;
          *(float *)(iVar7 + 0x2a0) = FLOAT_803e3c4c;
          FUN_8002b95c((int)param_9,1);
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
    }
    else {
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
    }
  }
  else if (cVar1 == '\x03') {
    iVar4 = FUN_8002bac4();
    dVar11 = FUN_80021730((float *)(iVar4 + 0x18),(float *)(param_9 + 0xc));
    if ((double)FLOAT_803e3c50 <= dVar11) {
      *(float *)(iVar7 + 0x270) = *(float *)(iVar7 + 0x270) - FLOAT_803dc074;
      *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803dc074;
      if (FLOAT_803e3c00 <= *(float *)(iVar7 + 0x2a0)) {
        if (FLOAT_803e3c00 < *(float *)(iVar7 + 0x270)) {
          iVar4 = FUN_80036974((int)param_9,&local_84,&iStack_7c,&uStack_80);
          if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != param_9[0x23])) {
            *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
          }
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
      else {
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
    else {
      *(undefined2 *)(iVar7 + 0x298) = 0x195;
      *(undefined2 *)(iVar7 + 0x29a) = 0;
      *(float *)(iVar7 + 0x29c) = FLOAT_803e3c30;
      FUN_800379bc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,0x7000a,
                   (uint)param_9,iVar7 + 0x298,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar7 + 0x278) = 4;
    }
    FUN_80163e3c(param_9,iVar7);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar7);
  }
  else if (cVar1 == '\x04') {
    while (iVar4 = FUN_800375e4((int)param_9,&local_88,(uint *)0x0,(uint *)0x0), iVar4 != 0) {
      if (local_88 == 0x7000b) {
        FUN_80020000(0x194);
        FUN_8000bb38((uint)param_9,0x49);
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
  }
  else if (cVar1 == '\x06') {
    pfVar5 = *(float **)(iVar7 + 0x290);
    dVar12 = (double)(*pfVar5 - *(float *)(param_9 + 6));
    dVar13 = (double)(pfVar5[1] - *(float *)(param_9 + 8));
    dVar8 = (double)(pfVar5[2] - *(float *)(param_9 + 10));
    dVar11 = FUN_80293900((double)(float)(dVar8 * dVar8 +
                                         (double)(float)(dVar12 * dVar12 +
                                                        (double)(float)(dVar13 * dVar13))));
    *(float *)(iVar7 + 0x294) = FLOAT_803dc074 * FLOAT_803e3c30 + *(float *)(iVar7 + 0x294);
    fVar2 = FLOAT_803e3c54;
    *(float *)(param_9 + 0x12) =
         FLOAT_803e3c54 * (float)(dVar12 / dVar11) * *(float *)(iVar7 + 0x294);
    *(float *)(param_9 + 0x14) = fVar2 * (float)(dVar13 / dVar11) * *(float *)(iVar7 + 0x294);
    *(float *)(param_9 + 0x16) = fVar2 * (float)(dVar8 / dVar11) * *(float *)(iVar7 + 0x294);
    dVar11 = FUN_80021730((float *)(param_9 + 6),*(float **)(iVar7 + 0x290));
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    dVar12 = FUN_80021730((float *)(param_9 + 6),*(float **)(iVar7 + 0x290));
    fVar2 = FLOAT_803e3c30;
    if (dVar11 < dVar12) {
      *(float *)(param_9 + 6) =
           (**(float **)(iVar7 + 0x290) - *(float *)(param_9 + 6)) * FLOAT_803e3c30 +
           *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 4) - *(float *)(param_9 + 8)) * fVar2 +
           *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 8) - *(float *)(param_9 + 10)) * fVar2 +
           *(float *)(param_9 + 10);
    }
  }
  else if (cVar1 == '\a') {
    for (uVar6 = 0; (int)(uVar6 & 0xffff) < (int)FLOAT_803dc074; uVar6 = uVar6 + 1) {
      *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * fVar2;
    }
    *(undefined4 *)(param_9 + 6) = **(undefined4 **)(iVar7 + 0x290);
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 4);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 8);
  }
  else {
    dVar11 = (double)*(float *)(iVar7 + 0x270);
    if ((double)FLOAT_803e3c00 < dVar11) {
      *(float *)(iVar7 + 0x270) = (float)(dVar11 - (double)FLOAT_803dc074);
    }
    else {
      FUN_8002cc9c(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

