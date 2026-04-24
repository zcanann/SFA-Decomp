// Function: FUN_801b0244
// Entry: 801b0244
// Size: 876 bytes

void FUN_801b0244(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  fVar2 = FLOAT_803dc074;
  bVar1 = DAT_803dc070;
  if (param_9[0x23] == 0x1fa) {
    *(float *)(param_9 + 6) = *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
    *(float *)(param_9 + 8) = *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
    *(float *)(param_9 + 10) =
         *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x1f5,0,1,0xffffffff,0);
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0x374;
    param_9[1] = param_9[1] + (ushort)DAT_803dc070 * 300;
    dVar6 = (double)FLOAT_803e5468;
    dVar5 = (double)FLOAT_803dc074;
    *(float *)(param_9 + 0x14) = -(float)(dVar6 * dVar5 - (double)*(float *)(param_9 + 0x14));
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_8002cc9c(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  else {
    iVar4 = *(int *)(param_9 + 0x5c);
    if ((*(byte *)(iVar4 + 0x10) & 0x10) == 0) {
      if (*(char *)(iVar4 + 0x11) != '\0') {
        *(char *)(iVar4 + 0x11) = *(char *)(iVar4 + 0x11) + -1;
      }
      *param_9 = *param_9 + (ushort)bVar1 * 0x40;
      param_9[1] = param_9[1] + (ushort)bVar1 * -0x200;
      *(float *)(param_9 + 0x14) = FLOAT_803e548c * fVar2 + *(float *)(param_9 + 0x14);
      dVar5 = (double)(*(float *)(param_9 + 0x14) * fVar2);
      dVar6 = (double)(*(float *)(param_9 + 0x16) * fVar2);
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * fVar2),dVar5,dVar6,(int)param_9);
      if (FLOAT_803e5490 <= *(float *)(param_9 + 0x14)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) & 0xdf;
      }
      else if ((*(byte *)(iVar4 + 0x10) & 0x20) == 0) {
        FUN_8000bb38((uint)param_9,0x3dd);
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x20;
      }
      iVar3 = *(int *)(param_9 + 0x2a);
      if (iVar3 != 0) {
        *(undefined *)(iVar3 + 0x6e) = 0xb;
        *(undefined *)(iVar3 + 0x6f) = 1;
        *(undefined4 *)(iVar3 + 0x48) = 0x10;
        *(undefined4 *)(iVar3 + 0x4c) = 0x10;
        if (*(int *)(iVar3 + 0x50) != 0) {
          if (*(char *)(iVar4 + 0x11) == '\0') {
            *(undefined *)(iVar4 + 0x11) = 10;
            FUN_8009adfc((double)FLOAT_803e5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                         param_9,1,1,0,0,0,0,0);
          }
          else {
            FUN_8009adfc((double)FLOAT_803e5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                         param_9,0,1,0,0,0,0,0);
          }
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_9[3] = param_9[3] | 0x4000;
        }
        if ((*(byte *)(iVar3 + 0xad) & 1) != 0) {
          FUN_8009adfc((double)FLOAT_803e5494,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,
                       param_9,1,1,0,0,0,0,0);
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_9[3] = param_9[3] | 0x4000;
          return;
        }
      }
      if (*(float *)(param_9 + 8) < *(float *)(iVar4 + 8)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
      }
      if ((*(byte *)(iVar4 + 0x10) & 8) == 0) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 8;
      }
      if ((*(int *)(iVar4 + 4) != 0) && (iVar3 = FUN_8001dc28(*(int *)(iVar4 + 4)), iVar3 != 0)) {
        FUN_8001d774(*(int *)(iVar4 + 4));
      }
    }
    else {
      FUN_80035ff8((int)param_9);
    }
  }
  return;
}

