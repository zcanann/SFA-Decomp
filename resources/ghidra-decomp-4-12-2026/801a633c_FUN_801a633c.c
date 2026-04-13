// Function: FUN_801a633c
// Entry: 801a633c
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x801a6500) */
/* WARNING: Removing unreachable block (ram,0x801a634c) */

void FUN_801a633c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  DAT_803de7a0 = DAT_803de7a0 + 1;
  FUN_8000bb38(param_9,0x106);
  if (DAT_803de7a0 < 2) {
    uVar1 = FUN_80022264(0,1);
    uVar2 = FUN_80022264(0x32,0x3c);
    FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5120),
                 param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,
                 0,1,0);
  }
  else {
    uVar1 = FUN_80022264(0,1);
    uVar2 = FUN_80022264(0x32,0x3c);
    FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5120),
                 param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,
                 0,0,0);
  }
  *(undefined *)(iVar3 + 0x114) = 1;
  *(float *)(iVar3 + 0x110) = FLOAT_803e5100;
  *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
  FUN_80035a6c(param_9,(short)(int)(FLOAT_803e5104 *
                                   (float)((double)CONCAT44(0x43300000,
                                                            (uint)*(byte *)(*(int *)(param_9 + 0x50)
                                                                           + 0x62)) -
                                          DOUBLE_803e5128)));
  iVar3 = FUN_8002bac4();
  if ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) {
    dVar4 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18));
    if (dVar4 <= (double)FLOAT_803e5108) {
      dVar4 = (double)(FLOAT_803e510c - (float)(dVar4 / (double)FLOAT_803e5108));
      FUN_8000e670((double)(float)((double)FLOAT_803e5110 * dVar4),
                   (double)(float)((double)FLOAT_803e5114 * dVar4),(double)FLOAT_803e5118);
      FUN_80014acc((double)(float)((double)FLOAT_803e511c * dVar4));
    }
  }
  return;
}

