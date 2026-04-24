// Function: FUN_8016a54c
// Entry: 8016a54c
// Size: 712 bytes

/* WARNING: Removing unreachable block (ram,0x8016a7f8) */
/* WARNING: Removing unreachable block (ram,0x8016a7f0) */
/* WARNING: Removing unreachable block (ram,0x8016a7e8) */
/* WARNING: Removing unreachable block (ram,0x8016a56c) */
/* WARNING: Removing unreachable block (ram,0x8016a564) */
/* WARNING: Removing unreachable block (ram,0x8016a55c) */

void FUN_8016a54c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  int local_58;
  int local_54 [3];
  longlong local_48;
  
  if (0 < (int)*(uint *)(param_9 + 0x7a)) {
    local_54[2] = *(uint *)(param_9 + 0x7a) ^ 0x80000000;
    local_54[1] = 0x43300000;
    dVar2 = (double)(float)((double)CONCAT44(0x43300000,local_54[2]) - DOUBLE_803e3dc8);
    iVar1 = (int)(dVar2 - (double)FLOAT_803dc074);
    local_48 = (longlong)iVar1;
    *(int *)(param_9 + 0x7a) = iVar1;
    if (*(int *)(param_9 + 0x7a) < 1) {
      FUN_8002cc9c(dVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
  }
  if (*(char *)(param_9 + 0x1b) != '\0') {
    dVar5 = (double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074);
    dVar4 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
    dVar3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    dVar2 = dVar3;
    FUN_8002ba34(dVar5,dVar4,dVar3,(int)param_9);
    *(float *)(param_9 + 0x14) = FLOAT_803e3dbc * FLOAT_803dc074 + *(float *)(param_9 + 0x14);
    if (*(float *)(param_9 + 0x14) < FLOAT_803e3dc0) {
      *(float *)(param_9 + 0x14) = FLOAT_803e3dc0;
    }
    iVar1 = FUN_80021884();
    *param_9 = (short)iVar1 + -0x8000;
    FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar2 * dVar2)));
    iVar1 = FUN_80021884();
    param_9[1] = 0x4000 - (short)iVar1;
    FUN_80035eec((int)param_9,10,1,0);
    FUN_80036018((int)param_9);
    if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_8002bac4(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_8002ba84(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
        if ((double)*(float *)(param_9 + 8) < (double)FLOAT_803e3dc4) {
          FUN_8002cc9c((double)*(float *)(param_9 + 8),dVar4,dVar3,param_4,param_5,param_6,param_7,
                       param_8,(int)param_9);
        }
      }
      else {
        *(undefined *)(param_9 + 0x1b) = 0;
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x78;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
        for (local_58 = 0; local_58 < 0x19; local_58 = local_58 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,&local_58);
        }
        FUN_8000bb38((uint)param_9,0x279);
      }
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0;
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x78;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      for (local_54[0] = 0; local_54[0] < 0x19; local_54[0] = local_54[0] + 1) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,local_54);
      }
      FUN_8000bb38((uint)param_9,0x279);
    }
  }
  return;
}

