// Function: FUN_802ac71c
// Entry: 802ac71c
// Size: 880 bytes

/* WARNING: Removing unreachable block (ram,0x802aca68) */
/* WARNING: Removing unreachable block (ram,0x802aca60) */
/* WARNING: Removing unreachable block (ram,0x802aca58) */
/* WARNING: Removing unreachable block (ram,0x802ac73c) */
/* WARNING: Removing unreachable block (ram,0x802ac734) */
/* WARNING: Removing unreachable block (ram,0x802ac72c) */

void FUN_802ac71c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  float local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  undefined4 local_98;
  float local_94;
  undefined8 local_90;
  undefined8 local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined8 local_50;
  undefined8 local_48;
  
  dVar4 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
  local_90 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d0) ^ 0x80000000);
  iVar3 = (int)((double)(float)(local_90 - DOUBLE_803e8b58) * dVar4);
  local_88 = (double)(longlong)iVar3;
  *(short *)(param_3 + 0x4d0) = (short)iVar3;
  iVar3 = *(int *)(param_3 + 0x4b8);
  if ((iVar3 == 0) || (*(char *)(*(int *)(iVar3 + 0x50) + 0x58) == '\0')) {
    dVar4 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d6) ^ 0x80000000);
    *(short *)(param_3 + 0x4d6) = (short)(int)((double)(float)(local_48 - DOUBLE_803e8b58) * dVar4);
  }
  else {
    FUN_80038524(param_1,5,&local_a0,&local_a4,&local_a8,0);
    iVar1 = FUN_800396d0(iVar3,0);
    if (iVar1 == 0) {
      local_9c = *(float *)(iVar3 + 0xc);
      local_98 = *(undefined4 *)(iVar3 + 0x10);
      local_94 = *(float *)(iVar3 + 0x14);
    }
    else {
      FUN_80039608(iVar3,0,&local_9c);
    }
    FUN_80293900((double)((local_9c - local_a0) * (local_9c - local_a0) +
                         (local_94 - local_a8) * (local_94 - local_a8)));
    uVar2 = FUN_80021884();
    uVar2 = (uVar2 & 0xffff) - (uint)*(ushort *)(param_3 + 0x4d6);
    if (0x8000 < (int)uVar2) {
      uVar2 = uVar2 - 0xffff;
    }
    if ((int)uVar2 < -0x8000) {
      uVar2 = uVar2 + 0xffff;
    }
    local_88 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    uStack_7c = (uint)((float)(local_88 - DOUBLE_803e8b58) * FLOAT_803e8b4c);
    local_90 = (double)(longlong)(int)uStack_7c;
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    uStack_74 = (int)*(short *)(param_3 + 0x4d6) ^ 0x80000000;
    local_78 = 0x43300000;
    iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e8b58) * FLOAT_803dc074
                 + (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e8b58));
    local_70 = (longlong)iVar3;
    *(short *)(param_3 + 0x4d6) = (short)iVar3;
    uVar2 = FUN_80021884();
    iVar3 = (uVar2 & 0xffff) - (uint)*(ushort *)(param_3 + 0x478);
    if (0x8000 < iVar3) {
      iVar3 = iVar3 + -0xffff;
    }
    if (iVar3 < -0x8000) {
      iVar3 = iVar3 + 0xffff;
    }
    if (iVar3 < -0x1c70) {
      iVar3 = -0x1c70;
    }
    else if (0x1c70 < iVar3) {
      iVar3 = 0x1c70;
    }
    uVar2 = iVar3 - (uint)*(ushort *)(param_3 + 0x4d4);
    if (0x8000 < (int)uVar2) {
      uVar2 = uVar2 - 0xffff;
    }
    if ((int)uVar2 < -0x8000) {
      uVar2 = uVar2 + 0xffff;
    }
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d4) ^ 0x80000000);
    *(short *)(param_3 + 0x4d4) =
         (short)(int)((float)((double)CONCAT44(0x43300000,
                                               (int)((float)((double)CONCAT44(0x43300000,
                                                                              uVar2 ^ 0x80000000) -
                                                            DOUBLE_803e8b58) * FLOAT_803e8b4c) ^
                                               0x80000000) - DOUBLE_803e8b58) * FLOAT_803dc074 +
                     (float)(local_50 - DOUBLE_803e8b58));
    *(short *)(param_3 + 0x4d2) = *(short *)(param_3 + 0x4d4) / 2;
  }
  return;
}

