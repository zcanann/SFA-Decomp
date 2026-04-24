// Function: FUN_802988e4
// Entry: 802988e4
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x80298abc) */
/* WARNING: Removing unreachable block (ram,0x802988f4) */

int FUN_802988e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)

{
  float fVar1;
  int iVar2;
  ushort uVar3;
  short sVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_9 + 0x5c);
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
    fVar1 = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x280) = fVar1;
    *(float *)(param_9 + 0x12) = fVar1;
    *(float *)(param_9 + 0x14) = fVar1;
    *(float *)(param_9 + 0x16) = fVar1;
  }
  iVar2 = FUN_8029c15c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar2 == 0) {
    iVar2 = *DAT_803dd70c;
    (**(code **)(iVar2 + 0x30))(param_1,param_9,param_10,1);
    sVar4 = *param_9;
    *(short *)(iVar5 + 0x484) = sVar4;
    *(short *)(iVar5 + 0x478) = sVar4;
    uVar3 = FUN_80014e04(0);
    if ((uVar3 & 0x20) == 0) {
      *(code **)(param_10 + 0x308) = FUN_8029d028;
      iVar2 = 0x25;
    }
    else {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        *(byte *)(iVar5 + 0x3f6) = *(byte *)(iVar5 + 0x3f6) & 0xef;
      }
      if ((*(byte *)(iVar5 + 0x3f6) >> 4 & 1) == 0) {
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
        if ((param_9[0x50] != 0x458) && (sVar4 = FUN_8002f604((int)param_9), sVar4 == 0)) {
          FUN_8003042c((double)*(float *)(param_9 + 0x4c),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,param_9,0x458,0,iVar2,param_13,param_14,param_15,param_16);
          FUN_8002f66c((int)param_9,8);
        }
      }
      else {
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8b24;
        if (param_9[0x50] != 0x455) {
          FUN_80014acc((double)FLOAT_803e8b70);
          FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,0x455,0,iVar2,param_13,param_14,param_15,param_16);
          *(float *)(param_10 + 0x280) = -*(float *)(iVar5 + 0x88c);
        }
        if (*(char *)(param_10 + 0x346) != '\0') {
          *(byte *)(iVar5 + 0x3f6) = *(byte *)(iVar5 + 0x3f6) & 0xef;
        }
      }
      dVar6 = (double)FUN_802932a4((double)*(float *)(iVar5 + 0x888),(double)FLOAT_803dc074);
      *(float *)(param_10 + 0x280) = (float)((double)*(float *)(param_10 + 0x280) * dVar6);
      iVar2 = 0;
    }
  }
  return iVar2;
}

