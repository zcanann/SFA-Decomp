// Function: FUN_80231e6c
// Entry: 80231e6c
// Size: 444 bytes

void FUN_80231e6c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  double dVar4;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x20,0x617);
    uStack_44 = FUN_80022264(-(int)*(char *)(param_11 + 0x22),(int)*(char *)(param_11 + 0x22));
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(puVar2 + 4) =
         *(float *)(param_9 + 0xc) +
         (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e7de0);
    uStack_3c = FUN_80022264(-(int)*(char *)(param_11 + 0x23),(int)*(char *)(param_11 + 0x23));
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(puVar2 + 6) =
         *(float *)(param_9 + 0x10) +
         (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7de0);
    uStack_34 = FUN_80022264(-(int)*(char *)(param_11 + 0x24),(int)*(char *)(param_11 + 0x24));
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    dVar4 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7de0);
    *(float *)(puVar2 + 8) = (float)((double)*(float *)(param_9 + 0x14) + dVar4);
    *(undefined *)(puVar2 + 0xd) = 0;
    *(undefined *)((int)puVar2 + 0x19) = 0;
    *(undefined *)(puVar2 + 0xc) = 0;
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    iVar3 = FUN_8002b678(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar2);
    uStack_2c = (int)*(char *)(param_11 + 0x1c) ^ 0x80000000;
    local_30 = 0x43300000;
    local_58 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7de0) / FLOAT_803e7dd8;
    uStack_24 = (int)*(char *)(param_11 + 0x1d) ^ 0x80000000;
    local_28 = 0x43300000;
    local_54 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7de0) / FLOAT_803e7dd8;
    uStack_1c = (int)*(char *)(param_11 + 0x1e) ^ 0x80000000;
    local_20 = 0x43300000;
    local_50 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7de0) / FLOAT_803e7dd8;
    FUN_8023171c(iVar3,&local_58);
    FUN_802316ec(iVar3,(uint)*(ushort *)(param_11 + 0x1a));
  }
  return;
}

