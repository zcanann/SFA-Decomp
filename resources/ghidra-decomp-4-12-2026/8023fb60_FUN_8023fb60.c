// Function: FUN_8023fb60
// Entry: 8023fb60
// Size: 1932 bytes

/* WARNING: Removing unreachable block (ram,0x802402c8) */
/* WARNING: Removing unreachable block (ram,0x802402c0) */
/* WARNING: Removing unreachable block (ram,0x8023fb78) */
/* WARNING: Removing unreachable block (ram,0x8023fb70) */

void FUN_8023fb60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  undefined4 uVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  
  dVar8 = (double)FLOAT_803dd160;
  piVar5 = *(int **)(param_9 + 0x5c);
  if (*piVar5 == 0) {
    iVar2 = FUN_8002e1ac(0x47b77);
    *piVar5 = iVar2;
  }
  if (piVar5[1] == 0) {
    iVar2 = FUN_8022de2c();
    piVar5[1] = iVar2;
  }
  if (*(char *)((int)piVar5 + 0x27) == '\0') {
    *(undefined *)(param_9 + 0x1b) = 0xff;
    param_9[2] = 0;
    param_9[1] = 0;
    uVar4 = 0xffffffff;
    FUN_80035eec((int)param_9,5,2,-1);
    FUN_80036018((int)param_9);
    if ((short *)*piVar5 != (short *)0x0) {
      *param_9 = *(short *)*piVar5;
      dVar6 = DOUBLE_803e8238;
      if (*(char *)((int)piVar5 + 0x22) != '\0') {
        dVar8 = (double)(float)(dVar8 * (double)FLOAT_803e824c);
      }
      uStack_54 = DAT_803dd164 ^ 0x80000000;
      local_58 = 0x43300000;
      uStack_4c = DAT_803dd168 ^ 0x80000000;
      local_50 = 0x43300000;
      piVar5[7] = (int)((float)piVar5[7] +
                       (-(float)piVar5[6] /
                        (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e8238) -
                       (float)piVar5[7]) /
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8238));
      piVar5[6] = (int)((float)piVar5[6] + (float)piVar5[7]);
      uStack_44 = (int)*(short *)*piVar5 ^ 0x80000000;
      local_48 = 0x43300000;
      iVar2 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar6) + dVar8);
      local_40 = (longlong)iVar2;
      uStack_34 = (int)(short)iVar2 ^ 0x80000000;
      local_38 = 0x43300000;
      dVar8 = (double)FUN_802945e0();
      dVar6 = (double)FUN_80294964();
      *(float *)(param_9 + 6) =
           (float)((double)FLOAT_803dd158 * dVar8 + (double)*(float *)(*piVar5 + 0xc));
      *(float *)(param_9 + 8) = *(float *)(*piVar5 + 0x10) + FLOAT_803dd15c;
      param_3 = (double)(float)piVar5[6];
      param_2 = (double)FLOAT_803dd158;
      *(float *)(param_9 + 10) =
           (float)(param_3 + (double)(float)(param_2 * dVar6 + (double)*(float *)(*piVar5 + 0x14)));
    }
    bVar1 = *(char *)((int)piVar5 + 0x23) != *(char *)(piVar5 + 9);
    *(char *)(piVar5 + 9) = *(char *)((int)piVar5 + 0x23);
    switch(*(undefined *)((int)piVar5 + 0x23)) {
    case 0:
      if (bVar1) {
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032cec8;
      }
      break;
    case 1:
      if (bVar1) {
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032cedc;
      }
      if (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)) {
        *(undefined *)((int)piVar5 + 0x23) = 3;
      }
      break;
    case 2:
      if (bVar1) {
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,4,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032ced8;
      }
      if (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)) {
        *(undefined *)((int)piVar5 + 0x23) = 3;
        *(undefined *)(piVar5 + 9) = 3;
      }
      break;
    case 3:
      if (bVar1) {
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032cec8;
      }
      break;
    case 4:
      if (bVar1) {
        *(undefined *)((int)piVar5 + 0x29) = 0;
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032cecc;
      }
      if (*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) {
        local_7c = FLOAT_803e825c;
        if (*(char *)((int)piVar5 + 0x22) != '\0') {
          local_7c = FLOAT_803e8258;
        }
        local_60 = FLOAT_803e8244;
        local_5c = FLOAT_803e8244;
        local_78 = FLOAT_803e8244;
        local_74 = FLOAT_803e8244;
        local_64 = local_7c;
        FUN_8022db70(piVar5[1],&local_7c);
        FUN_80014acc((double)FLOAT_803e8260);
      }
      if (DOUBLE_803e8268 <= (double)*(float *)(param_9 + 0x4c)) {
        piVar5[5] = (int)FLOAT_803e8274;
      }
      else {
        piVar5[5] = (int)FLOAT_803e8270;
      }
      if ((FLOAT_803e8278 <= *(float *)(param_9 + 0x4c)) && (*(char *)((int)piVar5 + 0x29) == '\0'))
      {
        *(undefined *)((int)piVar5 + 0x29) = 1;
        FUN_8000bb38((uint)param_9,0x471);
      }
      if (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)) {
        FUN_8023ad80(*piVar5,1);
        *(undefined *)((int)piVar5 + 0x23) = 3;
      }
      FUN_8023f8f4((uint)param_9,piVar5);
      break;
    case 5:
      if (bVar1) {
        *(undefined *)((int)piVar5 + 0x29) = 0;
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,2,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032ced0;
      }
      if ((*(char *)((int)piVar5 + 0x22) != '\0') && (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)))
      {
        FUN_8023ad80(*piVar5,1);
        *(undefined *)((int)piVar5 + 0x23) = 3;
      }
      if (DOUBLE_803e8280 <= (double)*(float *)(param_9 + 0x4c)) {
        piVar5[5] = (int)FLOAT_803e8274;
      }
      else {
        piVar5[5] = (int)FLOAT_803e8288;
      }
      if (*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) {
        local_70 = FLOAT_803e8244;
        local_6c = FLOAT_803e828c;
        local_68 = FLOAT_803e8244;
        local_88 = FLOAT_803e8244;
        local_84 = FLOAT_803e828c;
        local_80 = FLOAT_803e8244;
        FUN_8022db70(piVar5[1],&local_88);
        FUN_80014acc((double)FLOAT_803e8260);
      }
      if (((FLOAT_803e8278 <= *(float *)(param_9 + 0x4c)) &&
          (*(float *)(param_9 + 0x4c) < FLOAT_803e8290)) && (*(char *)((int)piVar5 + 0x29) == '\0'))
      {
        *(undefined *)((int)piVar5 + 0x29) = 1;
        FUN_8000bb38((uint)param_9,0x472);
      }
      if ((FLOAT_803e8290 <= *(float *)(param_9 + 0x4c)) && (*(char *)((int)piVar5 + 0x29) != '\0'))
      {
        *(undefined *)((int)piVar5 + 0x29) = 0;
        FUN_8000bb38((uint)param_9,0x473);
      }
      if (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)) {
        if (*(char *)((int)piVar5 + 0x22) != '\0') {
          FUN_8023ad80(*piVar5,1);
        }
        *(undefined *)((int)piVar5 + 0x23) = 3;
      }
      FUN_8023f8f4((uint)param_9,piVar5);
      break;
    case 6:
      if (bVar1) {
        iVar2 = *(int *)(param_9 + 0x5c);
        FUN_8003042c((double)FLOAT_803e8244,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,3,0,uVar4,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar2 + 0x14) = DAT_8032ced4;
        *(undefined2 *)(piVar5 + 8) = 0xffff;
      }
      *(ushort *)(piVar5 + 8) = *(short *)(piVar5 + 8) - (ushort)DAT_803dc070;
      if (DOUBLE_803e8268 <= (double)*(float *)(param_9 + 0x4c)) {
        uVar7 = FUN_8000da78((uint)param_9,0x467);
        piVar5[5] = (int)FLOAT_803e8288;
        if (*(short *)(piVar5 + 8) < 0) {
          FUN_8023f754(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)piVar5);
          *(short *)(piVar5 + 8) = (short)DAT_803dd16c;
        }
      }
      else {
        piVar5[5] = (int)FLOAT_803e8288;
      }
      if (FLOAT_803e8248 <= *(float *)(param_9 + 0x4c)) {
        FUN_8023ad80(*piVar5,1);
        *(undefined *)((int)piVar5 + 0x23) = 3;
      }
      FUN_8023f8f4((uint)param_9,piVar5);
      break;
    case 9:
      if (*(char *)((int)piVar5 + 0x22) == '\0') {
        bVar3 = 2;
      }
      else {
        bVar3 = 4;
      }
      FUN_8023ad80(*piVar5,bVar3);
    }
    if (*(char *)((int)piVar5 + 0x23) == '\t') {
      param_9[3] = param_9[3] | 0x4000;
    }
    else {
      param_9[3] = param_9[3] & 0xbfff;
    }
    FUN_8002fb40((double)(float)piVar5[5],(double)FLOAT_803dc074);
  }
  else {
    *(char *)((int)piVar5 + 0x27) = *(char *)((int)piVar5 + 0x27) + -1;
  }
  return;
}

