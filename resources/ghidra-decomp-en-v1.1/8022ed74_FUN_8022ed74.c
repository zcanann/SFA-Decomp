// Function: FUN_8022ed74
// Entry: 8022ed74
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x8022efec) */
/* WARNING: Removing unreachable block (ram,0x8022ed84) */

void FUN_8022ed74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  double dVar5;
  uint uStack_58;
  undefined4 uStack_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_28;
  uint uStack_24;
  
  pbVar4 = *(byte **)(param_9 + 0xb8);
  iVar1 = FUN_8022de2c();
  if ((*(short *)(param_9 + 0x46) == 0x80d) &&
     (iVar2 = FUN_80036974(param_9,&uStack_54,(int *)0x0,&uStack_58), iVar2 != 0)) {
    FUN_8009adfc((double)FLOAT_803e7cac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,0,0,1,0,0,3);
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
    FUN_80035ff8(param_9);
    *(float *)(pbVar4 + 0x10) = FLOAT_803e7cc0;
  }
  if ((*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0) && (pbVar4[1] == 0)) {
    if (*(short *)(param_9 + 0x46) != 0x6ae) {
      FUN_8000b4f0(param_9,0x2b3,4);
    }
    if (*(short *)(param_9 + 0x46) == 0x7e4) {
      iVar2 = FUN_80021884();
      uStack_24 = (int)(short)-(short)iVar2 ^ 0x80000000;
      local_28 = 0x43300000;
      dVar5 = (double)FUN_802945e0();
      local_44 = (float)((double)FLOAT_803e7cc4 * dVar5);
      dVar5 = (double)FUN_80294964();
      local_4c = (float)((double)FLOAT_803e7cd0 * dVar5);
      local_3c = FLOAT_803e7ca0;
      local_50 = local_44;
      local_48 = FLOAT_803e7ca0;
      local_40 = local_4c;
      FUN_8022db70(iVar1,&local_50);
      FUN_80014acc((double)FLOAT_803e7cd4);
    }
    if ((*(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar1) &&
       (uVar3 = FUN_8022ddfc(iVar1), uVar3 != 0)) {
      FUN_80247ef8((float *)(param_9 + 0x24),(float *)(param_9 + 0x24));
      local_38 = *(float *)(param_9 + 0xc) - *(float *)(iVar1 + 0xc);
      local_34 = *(float *)(param_9 + 0x10) - *(float *)(iVar1 + 0x10);
      local_30 = *(float *)(param_9 + 0x14) - *(float *)(iVar1 + 0x14);
      FUN_80247ef8(&local_38,&local_38);
      FUN_80247fec((float *)(param_9 + 0x24),&local_38,(float *)(param_9 + 0x24));
      *(float *)(param_9 + 0x24) = *(float *)(param_9 + 0x24) * *(float *)(pbVar4 + 8);
      *(float *)(param_9 + 0x28) = *(float *)(param_9 + 0x28) * *(float *)(pbVar4 + 8);
      *(float *)(param_9 + 0x2c) = *(float *)(param_9 + 0x2c) * *(float *)(pbVar4 + 8);
      pbVar4[1] = 1;
    }
    *(float *)(pbVar4 + 0x10) = FLOAT_803e7cc0;
    *(undefined *)(param_9 + 0x36) = 0;
    FUN_800998ec(param_9,(uint)*pbVar4);
    if (*(uint *)(pbVar4 + 0x14) != 0) {
      FUN_8001f448(*(uint *)(pbVar4 + 0x14));
      pbVar4[0x14] = 0;
      pbVar4[0x15] = 0;
      pbVar4[0x16] = 0;
      pbVar4[0x17] = 0;
    }
  }
  return;
}

