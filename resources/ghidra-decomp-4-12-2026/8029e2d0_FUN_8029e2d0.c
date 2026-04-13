// Function: FUN_8029e2d0
// Entry: 8029e2d0
// Size: 2180 bytes

/* WARNING: Removing unreachable block (ram,0x8029eb34) */
/* WARNING: Removing unreachable block (ram,0x8029eb2c) */
/* WARNING: Removing unreachable block (ram,0x8029e2e8) */
/* WARNING: Removing unreachable block (ram,0x8029e2e0) */

void FUN_8029e2d0(undefined8 param_1,undefined8 param_2,double param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  float fVar4;
  undefined2 *puVar5;
  int iVar6;
  char cVar8;
  short sVar7;
  int iVar9;
  int in_r6;
  undefined4 *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int iVar10;
  int iVar11;
  double dVar12;
  double dVar13;
  undefined8 extraout_f1;
  double dVar14;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  float fStack_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar15 = FUN_80286830();
  puVar5 = (undefined2 *)((ulonglong)uVar15 >> 0x20);
  iVar9 = (int)uVar15;
  iVar11 = *(int *)(puVar5 + 0x5c);
  iVar10 = -1;
  bVar3 = true;
  bVar2 = false;
  local_64 = DAT_803e8b10;
  local_60 = DAT_803e8b14;
  uVar15 = extraout_f1;
  FUN_8011f6d0(0xf);
  if (*(char *)(iVar9 + 0x27a) != '\0') {
    *(byte *)(iVar11 + 0x3f3) =
         *(byte *)(iVar11 + 0x3f3) >> 3 & 1 | *(byte *)(iVar11 + 0x3f3) & 0xfe;
    *(undefined2 *)(iVar9 + 0x278) = 0x1d;
    *(code **)(iVar11 + 0x898) = FUN_8029e240;
  }
  if (*(char *)(iVar9 + 0x27a) != '\0') {
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar11 + 0x8b4) = 1;
      *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7 | 8;
    }
    if ((*(char *)(iVar11 + 0x8c8) != 'H') && (*(char *)(iVar11 + 0x8c8) != 'G')) {
      FUN_80101c10(2);
      in_r6 = 8;
      in_r7 = &local_64;
      in_r8 = 0x1e;
      in_r9 = 0xff;
      in_r10 = *DAT_803dd6d0;
      (**(code **)(in_r10 + 0x1c))(0x52,1,0);
    }
    *(undefined *)(iVar11 + 0x86d) = 0;
    *(undefined *)(iVar11 + 0x86e) = 0;
    dVar14 = (double)*(float *)(iVar11 + 0x65c);
    iVar6 = FUN_80021884();
    *(short *)(iVar11 + 0x478) = (short)iVar6;
    *(undefined2 *)(iVar11 + 0x484) = *(undefined2 *)(iVar11 + 0x478);
    *puVar5 = *(undefined2 *)(iVar11 + 0x478);
    *(byte *)(iVar11 + 0x3f2) = *(byte *)(iVar11 + 0x3f2) & 0xfe | 1;
    FUN_8003042c((double)FLOAT_803e8b3c,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar5,0x5f,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    FUN_8002f66c((int)puVar5,8);
    *(float *)(iVar9 + 0x2a0) = FLOAT_803e8b90;
    fVar4 = FLOAT_803e8b3c;
    *(float *)(iVar11 + 0x444) = FLOAT_803e8b3c;
    *(float *)(iVar11 + 0x448) = fVar4;
    *(byte *)(iVar11 + 0x3f3) = *(byte *)(iVar11 + 0x3f3) & 0x7f;
    FUN_80035f84((int)puVar5);
  }
  *(float *)(iVar11 + 0x7bc) = FLOAT_803e8bc4;
  fVar4 = FLOAT_803e8b3c;
  *(float *)(iVar11 + 0x7b8) = FLOAT_803e8b3c;
  *(float *)(iVar9 + 0x280) = fVar4;
  *(float *)(iVar9 + 0x284) = fVar4;
  iVar6 = *(int *)(iVar11 + 0x67c);
  switch(puVar5[0x50]) {
  case 0x4d:
  case 0x4e:
  case 0x5a:
  case 0x65:
    if (*(char *)(iVar9 + 0x346) != '\0') {
      *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x800000;
      *(code **)(iVar9 + 0x308) = FUN_802a58ac;
      goto LAB_8029eb2c;
    }
    bVar2 = true;
    bVar3 = false;
    break;
  case 0x5f:
    if ((*(uint *)(iVar9 + 0x318) & 0x100) == 0) {
      *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x800000;
      *(code **)(iVar9 + 0x308) = FUN_802a58ac;
      goto LAB_8029eb2c;
    }
  }
  bVar1 = *(byte *)(iVar11 + 0x86d);
  cVar8 = FUN_80014cec(0);
  uStack_54 = (int)cVar8 ^ 0x80000000;
  local_58 = 0x43300000;
  dVar12 = (double)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e8b58) /
                   FLOAT_803e8c40);
  dVar14 = (double)FLOAT_803e8b64;
  if ((dVar14 <= dVar12) && (dVar14 = dVar12, (double)FLOAT_803e8b78 < dVar12)) {
    dVar14 = (double)FLOAT_803e8b78;
  }
  cVar8 = FUN_80014c98(0);
  uStack_4c = (int)cVar8 ^ 0x80000000;
  local_50 = 0x43300000;
  dVar13 = (double)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58) /
                   FLOAT_803e8c40);
  dVar12 = (double)FLOAT_803e8b64;
  if ((dVar12 <= dVar13) && (dVar12 = dVar13, (double)FLOAT_803e8b78 < dVar13)) {
    dVar12 = (double)FLOAT_803e8b78;
  }
  if (-1 < *(char *)(iVar11 + 0x3f3)) {
    if (dVar12 <= (double)FLOAT_803e8bac) {
      if ((double)FLOAT_803e8c78 <= dVar12) {
        if (dVar14 <= (double)FLOAT_803e8bac) {
          if ((double)FLOAT_803e8c78 <= dVar14) {
            if ((((*(float *)(iVar11 + 0x444) <= FLOAT_803e8c04) &&
                 (FLOAT_803e8c74 <= *(float *)(iVar11 + 0x444))) &&
                (*(float *)(iVar11 + 0x448) <= FLOAT_803e8c04)) &&
               (FLOAT_803e8c74 <= *(float *)(iVar11 + 0x448))) {
              *(undefined *)(iVar11 + 0x86d) = 0;
              iVar10 = 0x5f;
              *(float *)(iVar9 + 0x2a0) = FLOAT_803e8b90;
            }
            param_3 = (double)FLOAT_803e8b3c;
            param_4 = param_3;
          }
          else {
            param_4 = (double)FLOAT_803e8b3c;
            *(float *)(iVar11 + 0x444) = FLOAT_803e8b3c;
            param_3 = (double)(float)((double)FLOAT_803e8b44 * dVar14 + (double)FLOAT_803e8c74);
            *(undefined *)(iVar11 + 0x86d) = 4;
          }
        }
        else {
          param_4 = (double)FLOAT_803e8b3c;
          *(float *)(iVar11 + 0x444) = FLOAT_803e8b3c;
          param_3 = (double)(float)((double)FLOAT_803e8b44 * dVar14 + (double)FLOAT_803e8c04);
          *(undefined *)(iVar11 + 0x86d) = 3;
        }
      }
      else {
        dVar13 = (double)FLOAT_803e8be0;
        dVar14 = (double)FLOAT_803e8c04;
        param_3 = (double)FLOAT_803e8b3c;
        *(float *)(iVar11 + 0x448) = FLOAT_803e8b3c;
        *(undefined *)(iVar11 + 0x86d) = 2;
        param_4 = -(double)(float)(dVar13 * dVar12 - dVar14);
      }
    }
    else {
      dVar13 = (double)FLOAT_803e8be0;
      dVar14 = (double)FLOAT_803e8c74;
      param_3 = (double)FLOAT_803e8b3c;
      *(float *)(iVar11 + 0x448) = FLOAT_803e8b3c;
      *(undefined *)(iVar11 + 0x86d) = 1;
      param_4 = -(double)(float)(dVar13 * dVar12 - dVar14);
    }
    dVar12 = (double)FLOAT_803e8b94;
    *(float *)(iVar11 + 0x444) =
         (float)(dVar12 * (double)(float)(param_4 - (double)*(float *)(iVar11 + 0x444)) +
                (double)*(float *)(iVar11 + 0x444));
    *(float *)(iVar11 + 0x448) =
         (float)(dVar12 * (double)(float)(param_3 - (double)*(float *)(iVar11 + 0x448)) +
                (double)*(float *)(iVar11 + 0x448));
  }
  if ((-1 < *(char *)(iVar11 + 0x3f3)) &&
     ((((*(uint *)(iVar9 + 0x318) & 0x100) == 0 || (*(char *)(iVar11 + 0x681) != '\0')) ||
      (((*(byte *)(iVar11 + 0x3f1) & 1) == 0 && (FLOAT_803e8bf0 <= *(float *)(iVar9 + 0x1b0))))))) {
    if (*(char *)(iVar11 + 0x86d) == 0) {
      *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x800000;
      *(code **)(iVar9 + 0x308) = FUN_802a58ac;
      goto LAB_8029eb2c;
    }
    FUN_8003042c((double)FLOAT_803e8b30,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar5,*(undefined4 *)(*(char *)(iVar11 + 0x86d) * 4 + -0x7fcca938),0,in_r6,in_r7,
                 in_r8,in_r9,in_r10);
    *(float *)(iVar9 + 0x2a0) = FLOAT_803e8bb8;
    *(undefined *)(iVar11 + 0x86d) = 0;
    *(byte *)(iVar11 + 0x3f3) = *(byte *)(iVar11 + 0x3f3) & 0x7f | 0x80;
  }
  if (-1 < *(char *)(iVar11 + 0x3f3)) {
    if (*(char *)(iVar11 + 0x86d) != '\0') {
      DAT_803df104 = DAT_803df104 - DAT_803dc070;
      if ((int)DAT_803df104 < 1) {
        DAT_803df104 = FUN_80022264(0xb4,0xf0);
        FUN_8000bb38((uint)puVar5,0x2b);
      }
      *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x200;
      if (((int)*(char *)(iVar11 + 0x86d) == (uint)bVar1) && ((int)*(char *)(iVar11 + 0x86e) != 0))
      {
        if ((int)*(char *)(iVar11 + 0x86d) == (int)*(char *)(iVar11 + 0x86e)) {
          if (((*(byte *)(iVar11 + 0x3f3) >> 3 & 1) == 0) || ((*(byte *)(iVar11 + 0x3f3) & 1) != 0))
          {
            *(byte *)(iVar11 + 0x3f2) = *(byte *)(iVar11 + 0x3f2) & 0xfe;
          }
          else {
            *(byte *)(iVar11 + 0x3f2) = *(byte *)(iVar11 + 0x3f2) & 0xfe | 1;
            *(undefined *)(iVar11 + 0x86e) = 0;
          }
        }
      }
      else {
        *(byte *)(iVar11 + 0x3f2) = *(byte *)(iVar11 + 0x3f2) & 0xfe | 1;
        *(undefined *)(iVar11 + 0x86e) = 0;
      }
      if ((*(byte *)(iVar11 + 0x3f2) & 1) == 0) {
        if (((int)(short)puVar5[0x50] != *(int *)(&DAT_803356d8 + *(char *)(iVar11 + 0x86d) * 4)) ||
           (FLOAT_803e8c7c <= *(float *)(puVar5 + 0x4c))) {
          uStack_4c = FUN_80022264(0,100);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar9 + 0x2a0) =
               FLOAT_803e8c10 *
               ((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58) / FLOAT_803e8bf4)
               + *(float *)(&DAT_80335708 + *(char *)(iVar11 + 0x86d) * 4);
        }
        iVar10 = *(int *)(&DAT_803356d8 + *(char *)(iVar11 + 0x86d) * 4);
      }
      else {
        *(float *)(iVar9 + 0x2a0) =
             FLOAT_803e8b90 * *(float *)(iVar9 + 0x298) +
             *(float *)(&DAT_803356f8 + *(char *)(iVar11 + 0x86d) * 4);
        iVar10 = *(int *)(&DAT_803356e8 + *(char *)(iVar11 + 0x86d) * 4);
      }
    }
    if (*(char *)(iVar11 + 0x86d) == '\0') {
      dVar14 = (double)FLOAT_803e8b3c;
      dVar12 = dVar14;
    }
    else {
      dVar14 = (double)*(float *)(iVar11 + 0x444);
      dVar12 = (double)*(float *)(iVar11 + 0x448);
    }
    in_r6 = **(int **)(iVar6 + 0x68);
    cVar8 = (**(code **)(in_r6 + 0x20))(dVar14,iVar6,puVar5,(int)*(char *)(iVar11 + 0x86d));
    if (cVar8 == '\x01') {
      *(undefined *)(iVar11 + 0x86e) = 1;
    }
    else if (cVar8 == '\x02') {
      *(undefined *)(iVar11 + 0x86e) = 2;
    }
    else if (cVar8 == '\x03') {
      *(undefined *)(iVar11 + 0x86e) = 4;
    }
    else if (cVar8 == '\x04') {
      *(undefined *)(iVar11 + 0x86e) = 3;
    }
    else if (cVar8 == '\x05') {
      *(undefined *)(iVar11 + 0x681) = 1;
    }
    else {
      *(undefined *)(iVar11 + 0x86e) = 0;
    }
  }
  if (((iVar10 != -1) && ((short)puVar5[0x50] != iVar10)) &&
     (sVar7 = FUN_8002f604((int)puVar5), sVar7 == 0)) {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar5,iVar10,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    FUN_8002f66c((int)puVar5,10);
  }
  if (bVar2) {
    (**(code **)(*DAT_803dd70c + 0x20))(uVar15,puVar5,iVar9,3);
  }
  if (bVar3) {
    FUN_8000e0c0((double)*(float *)(iVar11 + 0x664),(double)*(float *)(iVar11 + 0x668),
                 (double)*(float *)(iVar11 + 0x66c),(float *)(puVar5 + 6),&fStack_68,
                 (float *)(puVar5 + 10),iVar6);
    fVar4 = FLOAT_803e8c50;
    *(float *)(puVar5 + 6) = FLOAT_803e8c50 * *(float *)(iVar11 + 0x654) + *(float *)(puVar5 + 6);
    *(float *)(puVar5 + 10) = fVar4 * *(float *)(iVar11 + 0x65c) + *(float *)(puVar5 + 10);
  }
  *(byte *)(iVar11 + 0x3f3) = *(byte *)(iVar11 + 0x3f3) >> 3 & 1 | *(byte *)(iVar11 + 0x3f3) & 0xfe;
LAB_8029eb2c:
  FUN_8028687c();
  return;
}

