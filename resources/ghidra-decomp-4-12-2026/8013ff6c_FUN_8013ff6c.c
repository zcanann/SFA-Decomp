// Function: FUN_8013ff6c
// Entry: 8013ff6c
// Size: 732 bytes

/* WARNING: Removing unreachable block (ram,0x80140220) */
/* WARNING: Removing unreachable block (ram,0x80140218) */
/* WARNING: Removing unreachable block (ram,0x8013ff84) */
/* WARNING: Removing unreachable block (ram,0x8013ff7c) */
/* WARNING: Removing unreachable block (ram,0x8013ffb8) */

void FUN_8013ff6c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  bool bVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  if (*(char *)((int)param_10 + 10) != '\x01') {
    if (*(char *)((int)param_10 + 10) != '\0') {
      return;
    }
    uVar4 = FUN_80020078(0x48b);
    *(byte *)(param_10 + 0x1c0) = (byte)((uVar4 & 0xff) << 4) | *(byte *)(param_10 + 0x1c0) & 0xf;
    param_10[0x1c4] = 0;
    *(undefined *)((int)param_10 + 10) = 1;
  }
  uVar5 = FUN_80020078(0x48b);
  bVar1 = *(byte *)(param_10 + 0x1c0) >> 4;
  uVar4 = (uint)bVar1;
  if (uVar4 != uVar5) {
    *(byte *)(param_10 + 0x1c0) = (bVar1 + 1) * '\x10' | *(byte *)(param_10 + 0x1c0) & 0xf;
    *(char *)*param_10 = *(char *)*param_10 + -2;
  }
  pfVar6 = (float *)FUN_801ce424(param_10[9]);
  iVar7 = FUN_80163d68(pfVar6);
  if ((iVar7 == 0) || (*(char *)*param_10 == '\0')) {
    *(undefined *)(param_10 + 2) = 1;
    *(undefined *)((int)param_10 + 10) = 0;
    fVar3 = FLOAT_803e306c;
    param_10[0x1c7] = FLOAT_803e306c;
    param_10[0x1c8] = fVar3;
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    param_10[0x15] = param_10[0x15] & 0xfffeffff;
    param_10[0x15] = param_10[0x15] & 0xfffdffff;
    param_10[0x15] = param_10[0x15] & 0xfffbffff;
    *(undefined *)((int)param_10 + 0xd) = 0xff;
  }
  else {
    if ((iVar7 != param_10[0x1c4]) && ((undefined4 *)param_10[10] != param_10 + 0x1c1)) {
      param_10[10] = param_10 + 0x1c1;
      param_10[0x15] = param_10[0x15] & 0xfffffbff;
      *(undefined2 *)((int)param_10 + 0xd2) = 0;
    }
    dVar10 = (double)(*pfVar6 - *(float *)(param_9 + 0x18));
    dVar9 = (double)(pfVar6[2] - *(float *)(param_9 + 0x20));
    dVar8 = FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
    if ((double)FLOAT_803e306c != dVar8) {
      dVar10 = (double)(float)(dVar10 / dVar8);
      dVar9 = (double)(float)(dVar9 / dVar8);
    }
    dVar8 = (double)FLOAT_803e3164;
    param_10[0x1c1] = -(float)(dVar8 * dVar10 - (double)*(float *)(iVar7 + 0x18));
    param_10[0x1c2] = *(undefined4 *)(iVar7 + 0x1c);
    param_10[0x1c3] = -(float)(dVar8 * dVar9 - (double)*(float *)(iVar7 + 0x20));
    iVar7 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,uVar4,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar7 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar2 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar2 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
        param_10[0x1e7] = FLOAT_803e30d0;
        param_10[0x20e] = FLOAT_803e306c;
        FUN_80148ff0();
      }
      else {
        FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
        FUN_80148ff0();
      }
    }
  }
  return;
}

