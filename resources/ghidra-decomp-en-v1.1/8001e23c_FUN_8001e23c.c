// Function: FUN_8001e23c
// Entry: 8001e23c
// Size: 812 bytes

void FUN_8001e23c(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  int iVar5;
  float *pfVar6;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  float local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  pfVar6 = (float *)FUN_8000f56c();
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 == 4) {
    if (param_2 == 0) {
      local_60 = FLOAT_803df3dc;
      local_5c = FLOAT_803df3dc;
      local_58 = FLOAT_803df3dc;
    }
    else if (*(int *)(param_1 + 0x60) == 0) {
      local_78 = *(float *)(param_2 + 0xc) - FLOAT_803dda58;
      local_74 = *(undefined4 *)(param_2 + 0x10);
      local_70 = *(float *)(param_2 + 0x14) - FLOAT_803dda5c;
      FUN_80247bf8(pfVar6,&local_78,&local_60);
    }
    else {
      local_60 = *(float *)(param_2 + 0xc);
      local_5c = *(float *)(param_2 + 0x10);
      local_58 = *(float *)(param_2 + 0x14);
    }
    FUN_80247edc((double)FLOAT_803df424,(float *)(param_1 + 0x40),(float *)(param_1 + 0x1c));
    FUN_80247e94((float *)(param_1 + 0x1c),&local_60,&local_60);
    FUN_8025a07c((double)local_60,(double)local_5c,(double)local_58,param_1 + 0x68);
    local_88 = *(undefined4 *)(param_1 + 0xa8);
    FUN_8025a17c(param_1 + 0x68,(byte *)&local_88);
    FUN_80259e00((double)FLOAT_803df3e0,(double)FLOAT_803df3dc,(double)FLOAT_803df3dc,param_1 + 0x68
                );
  }
  else {
    if (iVar5 < 4) {
      if (iVar5 != 2) goto LAB_8001e540;
    }
    else if (iVar5 != 8) goto LAB_8001e540;
    if (DAT_803dd6b1 == '\0') {
      FUN_8025a07c((double)*(float *)(param_1 + 0x1c),(double)*(float *)(param_1 + 0x20),
                   (double)*(float *)(param_1 + 0x24),param_1 + 0x68);
    }
    else {
      if (*(int *)(param_1 + 0x60) == 0) {
        local_6c = *(float *)(param_2 + 0xc) - FLOAT_803dda58;
        local_68 = *(undefined4 *)(param_2 + 0x10);
        local_64 = *(float *)(param_2 + 0x14) - FLOAT_803dda5c;
        FUN_80247bf8(pfVar6,&local_6c,&local_60);
      }
      else {
        local_60 = *(float *)(param_2 + 0xc);
        local_5c = *(float *)(param_2 + 0x10);
        local_58 = *(float *)(param_2 + 0x14);
      }
      FUN_80247eb8((float *)(param_1 + 0x1c),&local_60,&local_60);
      FUN_8025a07c((double)local_60,(double)local_5c,(double)local_58,param_1 + 0x68);
    }
    FUN_8025a08c((double)*(float *)(param_1 + 0x40),(double)*(float *)(param_1 + 0x44),
                 (double)*(float *)(param_1 + 0x48),param_1 + 0x68);
    if ((param_2 == 0) || ((*(uint *)(*(int *)(param_2 + 0x50) + 0x44) & 0x10) != 0)) {
      local_84 = *(undefined4 *)(param_1 + 0xa8);
      FUN_8025a17c(param_1 + 0x68,(byte *)&local_84);
      FUN_80259e00((double)*(float *)(param_1 + 0x124),(double)*(float *)(param_1 + 0x128),
                   (double)*(float *)(param_1 + 300),param_1 + 0x68);
    }
    else {
      uStack_4c = (uint)*(byte *)(param_1 + 0xa8);
      local_50 = 0x43300000;
      fVar4 = *(float *)(param_1 + 0x134);
      iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df3f0) * fVar4);
      local_48 = (longlong)iVar5;
      uStack_3c = (uint)*(byte *)(param_1 + 0xa9);
      local_40 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df3f0) * fVar4);
      local_38 = (longlong)iVar1;
      uStack_2c = (uint)*(byte *)(param_1 + 0xaa);
      local_30 = 0x43300000;
      iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3f0) * fVar4);
      local_28 = (longlong)iVar2;
      uStack_1c = (uint)*(byte *)(param_1 + 0xab);
      local_20 = 0x43300000;
      iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df3f0) * fVar4);
      local_18 = (longlong)iVar3;
      local_80 = CONCAT31(CONCAT21(CONCAT11((char)iVar5,(char)iVar1),(char)iVar2),(char)iVar3);
      local_7c = local_80;
      FUN_8025a17c(param_1 + 0x68,(byte *)&local_80);
      FUN_80259e00((double)FLOAT_803df3e0,(double)FLOAT_803df3dc,(double)FLOAT_803df3dc,
                   param_1 + 0x68);
    }
  }
LAB_8001e540:
  FUN_8025a1a4(param_1 + 0x68,param_3);
  return;
}

