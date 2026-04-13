// Function: FUN_801f5a60
// Entry: 801f5a60
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x801f5c0c) */
/* WARNING: Removing unreachable block (ram,0x801f5a70) */

void FUN_801f5a60(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  double dVar6;
  uint local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  
  puVar5 = *(undefined4 **)(param_9 + 0x5c);
  iVar4 = *(int *)(param_9 + 0x26);
  dVar6 = (double)FLOAT_803e6b40;
  while (iVar1 = FUN_800375e4((int)param_9,local_38,(uint *)0x0,(uint *)0x0), iVar1 != 0) {
    if (local_38[0] == 0x7000b) {
      param_9[3] = param_9[3] | 0x4000;
      *(float *)(*(int *)(param_9 + 0x5c) + 0x70) = (float)dVar6;
      FUN_80020000(0x13d);
      FUN_80020000(0x5d6);
      FUN_8000bb38((uint)param_9,0x49);
    }
  }
  if (*(char *)(puVar5 + 0x1b) < '\0') {
    iVar4 = FUN_80080434((float *)(puVar5 + 0x1d));
    if (iVar4 != 0) {
      puVar5[0x1c] = FLOAT_803e6b40;
    }
    dVar6 = (double)(float)puVar5[0x1c];
    if (dVar6 <= (double)FLOAT_803e6b5c) {
      FUN_801f55c0(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    else {
      puVar5[0x1c] = (float)(dVar6 - (double)FLOAT_803dc074);
      dVar6 = (double)(float)puVar5[0x1c];
      uStack_2c = (int)DAT_803dcd90 ^ 0x80000000;
      local_30 = 0x43300000;
      if ((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6b68) < dVar6) {
        FUN_80099c40((double)FLOAT_803e6b74,param_9,4,5);
      }
      if ((double)(float)puVar5[0x1c] <= (double)FLOAT_803e6b5c) {
        FUN_8002cc9c((double)(float)puVar5[0x1c],dVar6,param_3,param_4,param_5,param_6,param_7,
                     param_8,(int)param_9);
      }
    }
  }
  else {
    iVar1 = 0;
    if (((int)*(short *)(iVar4 + 0x20) == 0xffffffff) ||
       (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x20)), uVar2 != 0)) {
      iVar1 = 1;
    }
    *(byte *)(puVar5 + 0x1b) = (byte)(iVar1 << 7) | *(byte *)(puVar5 + 0x1b) & 0x7f;
    if (*(char *)(puVar5 + 0x1b) < '\0') {
      uVar3 = FUN_8001cd60(param_9,100,0xff,100,0);
      *puVar5 = uVar3;
    }
  }
  return;
}

