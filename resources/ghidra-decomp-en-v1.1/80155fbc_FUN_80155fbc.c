// Function: FUN_80155fbc
// Entry: 80155fbc
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x80156184) */
/* WARNING: Removing unreachable block (ram,0x80155fcc) */

void FUN_80155fbc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    local_2c = *(float *)(param_9 + 0xc);
    local_28 = FLOAT_803e36e0 + *(float *)(param_9 + 0x10);
    local_24 = *(undefined4 *)(param_9 + 0x14);
    iVar2 = *(int *)(param_10 + 0x29c);
    local_38 = *(float *)(iVar2 + 0xc);
    local_34 = FLOAT_803e36e4 + *(float *)(iVar2 + 0x10);
    local_30 = *(float *)(iVar2 + 0x14);
    uStack_1c = FUN_80022264(0xfffffff6,10);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    dVar5 = (double)(FLOAT_803e36e8 *
                    (FLOAT_803e36f0 *
                     (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3700) +
                    FLOAT_803e36ec));
    iVar2 = FUN_8016a3a0(dVar5,(double)FLOAT_803e36f4,&local_2c,&local_38,'\x01');
    FUN_80293778(iVar2,&local_40,&local_3c);
    local_3c = (float)((double)local_3c * dVar5);
    local_40 = (float)((double)local_40 * dVar5);
    dVar5 = (double)(local_38 - *(float *)(param_9 + 0xc));
    dVar4 = (double)(local_30 - *(float *)(param_9 + 0x14));
    if ((double)FLOAT_803e36f8 == dVar4) {
      local_44 = FLOAT_803e36f8;
    }
    else {
      iVar2 = FUN_80021884();
      FUN_80293778(iVar2,&local_48,&local_44);
      dVar5 = (double)local_3c;
      local_44 = (float)((double)local_44 * dVar5);
      local_3c = (float)(dVar5 * (double)local_48);
    }
    puVar3 = FUN_8002becc(0x24,0x47b);
    *(float *)(puVar3 + 4) = local_2c;
    *(float *)(puVar3 + 6) = local_28;
    *(undefined4 *)(puVar3 + 8) = local_24;
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar2 = FUN_8002e088(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff,
                         0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar2 != 0) {
      *(float *)(iVar2 + 0x24) = local_3c;
      *(float *)(iVar2 + 0x28) = local_40;
      *(float *)(iVar2 + 0x2c) = local_44;
      *(uint *)(iVar2 + 0xc4) = param_9;
      FUN_8000bb38(param_9,0x259);
    }
  }
  return;
}

