// Function: FUN_801fa3d4
// Entry: 801fa3d4
// Size: 1068 bytes

void FUN_801fa3d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  short sVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  short *psVar5;
  double dVar6;
  ushort local_48 [4];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  iVar4 = *(int *)(param_9 + 0x26);
  psVar5 = *(short **)(param_9 + 0x5c);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    sVar1 = *(short *)(iVar4 + 0x1a);
    if (sVar1 == 1) {
      uVar2 = FUN_80020078((int)*psVar5);
      if ((uVar2 != 0) || (*psVar5 == -1)) {
        local_30 = (double)(longlong)(int)FLOAT_803dc074;
        psVar5[2] = psVar5[2] - (short)(int)FLOAT_803dc074;
        if (psVar5[2] < 1) {
          psVar5[2] = psVar5[1];
          puVar3 = FUN_8002becc(0x28,0x263);
          *(undefined *)(puVar3 + 3) = 0xff;
          *(undefined *)((int)puVar3 + 7) = 0xff;
          *(undefined *)(puVar3 + 2) = 2;
          *(undefined *)((int)puVar3 + 5) = 1;
          uVar2 = FUN_80022264(-(int)psVar5[4],(int)psVar5[4]);
          local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
          *(float *)(puVar3 + 4) = *(float *)(param_9 + 6) + (float)(local_30 - DOUBLE_803e6d18);
          *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 8);
          uStack_24 = FUN_80022264(-(int)psVar5[4],(int)psVar5[4]);
          uStack_24 = uStack_24 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar6 = (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e6d18);
          *(float *)(puVar3 + 8) = (float)((double)*(float *)(param_9 + 10) + dVar6);
          puVar3[0x10] = 0x50;
          uVar2 = FUN_80022264(0,2);
          puVar3[0xf] = (short)uVar2 + 0x16a;
          puVar3[0x11] = 0xffff;
          uVar2 = FUN_80022264(0xfffffe0c,500);
          puVar3[0xc] = (short)uVar2 + 0x5dc;
          uVar2 = FUN_80022264(0xfffffe0c,500);
          puVar3[0xd] = (short)uVar2 + 0x5dc;
          uVar2 = FUN_80022264(0xfffffe0c,500);
          puVar3[0xe] = (short)uVar2 + 0x5dc;
          *(undefined *)(puVar3 + 0x12) = 0;
          iVar4 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                               5,*(undefined *)(param_9 + 0x56),0xffffffff,
                               *(uint **)(param_9 + 0x18),in_r8,in_r9,in_r10);
          if (iVar4 != 0) {
            uStack_24 = FUN_80022264(0,10);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            *(float *)(iVar4 + 0x28) =
                 FLOAT_803e6d04 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e6d18)
                 + FLOAT_803e6d00;
            uVar2 = FUN_80022264(0xfffffff6,10);
            local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
            *(float *)(iVar4 + 0x24) = FLOAT_803e6d08 * (float)(local_30 - DOUBLE_803e6d18);
            uVar2 = FUN_80022264(0xfffffff6,10);
            local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
            *(float *)(iVar4 + 0x2c) = FLOAT_803e6d08 * (float)(local_20 - DOUBLE_803e6d18);
          }
        }
      }
    }
    else if ((0 < sVar1) && (sVar1 == 6)) {
      local_20 = (double)(longlong)(int)FLOAT_803dc074;
      psVar5[2] = psVar5[2] - (short)(int)FLOAT_803dc074;
      if (psVar5[2] < 1) {
        psVar5[2] = psVar5[1];
        puVar3 = FUN_8002becc(0x24,0x549);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar4 + 8);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar4 + 0xc);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar4 + 0x10);
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar4 + 4);
        *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar4 + 5);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar4 + 6);
        *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar4 + 7);
        puVar3[0xf] = 0xffff;
        puVar3[0x10] = 0xffff;
        uVar2 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                             5,*(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),
                             in_r8,in_r9,in_r10);
        if (uVar2 != 0) {
          *(undefined4 *)(uVar2 + 0xf8) = 500;
          local_3c = FLOAT_803e6d0c;
          *(float *)(uVar2 + 0x28) = FLOAT_803e6d0c;
          *(float *)(uVar2 + 0x24) = local_3c;
          local_40 = FLOAT_803e6d10;
          *(float *)(uVar2 + 0x2c) = FLOAT_803e6d10;
          local_38 = local_3c;
          local_34 = local_3c;
          local_48[2] = 0;
          local_48[1] = 0;
          local_48[0] = *param_9;
          FUN_80021b8c(local_48,(float *)(uVar2 + 0x24));
          FUN_8000bb38(uVar2,0x10c);
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x39a,0,0x10002,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x39b,0,0x10002,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x39c,0,0x10002,0xffffffff,0);
        }
      }
    }
  }
  return;
}

