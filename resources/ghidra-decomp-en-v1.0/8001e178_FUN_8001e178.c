// Function: FUN_8001e178
// Entry: 8001e178
// Size: 812 bytes

void FUN_8001e178(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  float fVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 local_88;
  undefined4 local_84;
  uint local_80;
  uint local_7c;
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
  uint uStack76;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  uVar6 = FUN_8000f54c();
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 == 4) {
    if (param_2 == 0) {
      local_60 = FLOAT_803de75c;
      local_5c = FLOAT_803de75c;
      local_58 = FLOAT_803de75c;
    }
    else if (*(int *)(param_1 + 0x60) == 0) {
      local_78 = *(float *)(param_2 + 0xc) - FLOAT_803dcdd8;
      local_74 = *(undefined4 *)(param_2 + 0x10);
      local_70 = *(float *)(param_2 + 0x14) - FLOAT_803dcddc;
      FUN_80247494(uVar6,&local_78,&local_60);
    }
    else {
      local_60 = *(float *)(param_2 + 0xc);
      local_5c = *(float *)(param_2 + 0x10);
      local_58 = *(float *)(param_2 + 0x14);
    }
    FUN_80247778((double)FLOAT_803de7a4,param_1 + 0x40,param_1 + 0x1c);
    FUN_80247730(param_1 + 0x1c,&local_60,&local_60);
    FUN_80259918((double)local_60,(double)local_5c,(double)local_58,param_1 + 0x68);
    local_88 = *(undefined4 *)(param_1 + 0xa8);
    FUN_80259a18(param_1 + 0x68,&local_88);
    FUN_8025969c((double)FLOAT_803de760,(double)FLOAT_803de75c,(double)FLOAT_803de75c,param_1 + 0x68
                );
  }
  else {
    if (iVar5 < 4) {
      if (iVar5 != 2) goto LAB_8001e47c;
    }
    else if (iVar5 != 8) goto LAB_8001e47c;
    if (DAT_803dca31 == '\0') {
      FUN_80259918((double)*(float *)(param_1 + 0x1c),(double)*(float *)(param_1 + 0x20),
                   (double)*(float *)(param_1 + 0x24),param_1 + 0x68);
    }
    else {
      if (*(int *)(param_1 + 0x60) == 0) {
        local_6c = *(float *)(param_2 + 0xc) - FLOAT_803dcdd8;
        local_68 = *(undefined4 *)(param_2 + 0x10);
        local_64 = *(float *)(param_2 + 0x14) - FLOAT_803dcddc;
        FUN_80247494(uVar6,&local_6c,&local_60);
      }
      else {
        local_60 = *(float *)(param_2 + 0xc);
        local_5c = *(float *)(param_2 + 0x10);
        local_58 = *(float *)(param_2 + 0x14);
      }
      FUN_80247754(param_1 + 0x1c,&local_60,&local_60);
      FUN_80259918((double)local_60,(double)local_5c,(double)local_58,param_1 + 0x68);
    }
    FUN_80259928((double)*(float *)(param_1 + 0x40),(double)*(float *)(param_1 + 0x44),
                 (double)*(float *)(param_1 + 0x48),param_1 + 0x68);
    if ((param_2 == 0) || ((*(uint *)(*(int *)(param_2 + 0x50) + 0x44) & 0x10) != 0)) {
      local_84 = *(undefined4 *)(param_1 + 0xa8);
      FUN_80259a18(param_1 + 0x68,&local_84);
      FUN_8025969c((double)*(float *)(param_1 + 0x124),(double)*(float *)(param_1 + 0x128),
                   (double)*(float *)(param_1 + 300),param_1 + 0x68);
    }
    else {
      uStack76 = (uint)*(byte *)(param_1 + 0xa8);
      local_50 = 0x43300000;
      fVar4 = *(float *)(param_1 + 0x134);
      iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de770) * fVar4);
      local_48 = (longlong)iVar5;
      uStack60 = (uint)*(byte *)(param_1 + 0xa9);
      local_40 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803de770) * fVar4);
      local_38 = (longlong)iVar1;
      uStack44 = (uint)*(byte *)(param_1 + 0xaa);
      local_30 = 0x43300000;
      iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de770) * fVar4);
      local_28 = (longlong)iVar2;
      uStack28 = (uint)*(byte *)(param_1 + 0xab);
      local_20 = 0x43300000;
      uVar3 = (uint)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de770) * fVar4);
      local_18 = (longlong)(int)uVar3;
      local_7c = uVar3 & 0xff | (uint)CONCAT21(CONCAT11((char)iVar5,(char)iVar1),(char)iVar2) << 8;
      local_80 = local_7c;
      FUN_80259a18(param_1 + 0x68,&local_80);
      FUN_8025969c((double)FLOAT_803de760,(double)FLOAT_803de75c,(double)FLOAT_803de75c,
                   param_1 + 0x68);
    }
  }
LAB_8001e47c:
  FUN_80259a40(param_1 + 0x68,param_3);
  return;
}

