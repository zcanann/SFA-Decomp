// Function: FUN_801f9a74
// Entry: 801f9a74
// Size: 784 bytes

undefined4
FUN_801f9a74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11)

{
  byte bVar1;
  float fVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  float afStack_38 [3];
  undefined auStack_2c [6];
  undefined2 local_26;
  float local_20;
  float local_1c;
  float local_18 [2];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    bVar1 = *(byte *)(param_11 + iVar6 + 0x81);
    if (bVar1 == 2) {
      *(undefined *)(iVar5 + 0x68) = 0;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      puVar3 = FUN_8000facc();
      FUN_80247eb8((float *)(puVar3 + 6),(float *)(param_9 + 0xc),afStack_38);
      FUN_80247ef8(afStack_38,afStack_38);
      FUN_80247edc((double)FLOAT_803e6cd0,afStack_38,afStack_38);
      FUN_80247e94((float *)(param_9 + 0xc),afStack_38,(float *)(param_9 + 0xc));
      *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(param_9 + 0x1c) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(param_9 + 0x14);
      FUN_8009adfc((double)FLOAT_803e6cd0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,1,0,0,0,0,0);
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
      if (*(short *)(param_9 + 0x46) == 0x783) {
        FUN_800201ac(0xd27,0);
      }
    }
  }
  uVar4 = FUN_80020078(0xd27);
  if (uVar4 != 0) {
    if (*(short *)(param_9 + 0x46) == 0x783) {
      uVar4 = FUN_80020078(0xe49);
      if (uVar4 == 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x7ed,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x7ed,auStack_2c,2,0xffffffff,0);
      }
      FUN_80096c3c((double)FLOAT_803e6cd4,(double)FLOAT_803e6cd8,(double)FLOAT_803e6cdc,
                   (double)FLOAT_803e6ce0,(double)FLOAT_803e6cd0,param_9,iVar5,1);
      FUN_80096c3c((double)FLOAT_803e6cd4,(double)FLOAT_803e6cd8,(double)FLOAT_803e6ce4,
                   (double)FLOAT_803e6ce0,(double)FLOAT_803e6ce8,param_9,iVar5 + 0x34,1);
    }
    else if ((*(short *)(param_9 + 0x46) == 0x784) && (*(char *)(iVar5 + 0x68) != '\0')) {
      FUN_800383e8(param_9,0,&local_20,&local_1c,local_18);
      fVar2 = *(float *)(param_9 + 8);
      local_20 = local_20 * fVar2;
      local_1c = local_1c * fVar2;
      local_18[0] = local_18[0] * fVar2;
      local_26 = 1;
      FUN_80097568((double)FLOAT_803e6cec,(double)FLOAT_803e6cf0,param_9,5,1,1,10,(int)auStack_2c,0)
      ;
      FUN_800383e8(param_9,1,&local_20,&local_1c,local_18);
      fVar2 = *(float *)(param_9 + 8);
      local_20 = local_20 * fVar2;
      local_1c = local_1c * fVar2;
      local_18[0] = local_18[0] * fVar2;
      local_26 = 0;
      FUN_80097568((double)FLOAT_803e6cec,(double)FLOAT_803e6cf0,param_9,5,1,1,10,(int)auStack_2c,0)
      ;
    }
  }
  return 0;
}

