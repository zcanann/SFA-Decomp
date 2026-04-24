// Function: FUN_80200850
// Entry: 80200850
// Size: 544 bytes

undefined4 FUN_80200850(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24;
  float local_20;
  float local_1c;
  
  iVar4 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
  *(byte *)(iVar4 + 0x15) = *(byte *)(iVar4 + 0x15) & 0xfb;
  fVar1 = FLOAT_803e62f0;
  *(float *)(param_2 + 0x280) = *(float *)(param_2 + 0x280) / FLOAT_803e62f0;
  *(float *)(param_2 + 0x284) = *(float *)(param_2 + 0x284) / fVar1;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e62f4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,param_1,0x11,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 0x1f;
  if ((*(float *)(param_1 + 0x98) <= FLOAT_803e62ec) ||
     (*(float *)(param_1 + 0x10) < *(float *)(*(int *)(param_2 + 0x2d0) + 0x10) - FLOAT_803e62f8)) {
    iVar2 = *(int *)(param_2 + 0x2d0);
    local_24 = *(float *)(iVar2 + 0xc) - *(float *)(param_1 + 0xc);
    local_20 = *(float *)(iVar2 + 0x10) - (*(float *)(param_1 + 0x10) + FLOAT_803e62fc);
    local_1c = *(float *)(iVar2 + 0x14) - *(float *)(param_1 + 0x14);
    dVar5 = (double)FUN_802931a0((double)(local_1c * local_1c +
                                         local_24 * local_24 + local_20 * local_20));
    if (dVar5 < (double)FLOAT_803e62b8) {
      local_40 = *(undefined4 *)(param_2 + 0x2d0);
      uVar3 = *(undefined4 *)(iVar4 + 0x24);
      local_48 = 0xe;
      local_44 = 1;
      iVar2 = FUN_800138c4(uVar3);
      if (iVar2 == 0) {
        FUN_80013958(uVar3,&local_48);
      }
      *(undefined *)(iVar4 + 0x34) = 1;
    }
  }
  else {
    uVar3 = *(undefined4 *)(iVar4 + 0x24);
    local_30 = 9;
    local_2c = 0;
    local_28 = 0x24;
    iVar2 = FUN_800138c4(uVar3);
    if (iVar2 == 0) {
      FUN_80013958(uVar3,&local_30);
    }
    *(undefined *)(iVar4 + 0x34) = 1;
    local_34 = *(undefined4 *)(param_2 + 0x2d0);
    uVar3 = *(undefined4 *)(iVar4 + 0x24);
    local_3c = 7;
    local_38 = 1;
    iVar2 = FUN_800138c4(uVar3);
    if (iVar2 == 0) {
      FUN_80013958(uVar3,&local_3c);
    }
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  return 0;
}

