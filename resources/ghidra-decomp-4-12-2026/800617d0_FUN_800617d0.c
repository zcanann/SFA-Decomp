// Function: FUN_800617d0
// Entry: 800617d0
// Size: 768 bytes

void FUN_800617d0(ushort *param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  undefined2 *puVar3;
  undefined4 local_98;
  undefined4 local_94;
  float afStack_90 [16];
  float local_50;
  float local_4c;
  float local_48;
  float local_40;
  float local_3c;
  float local_38;
  float local_30;
  float local_2c;
  float local_28;
  
  puVar3 = *(undefined2 **)(param_2 + 0x54);
  if (*(char *)(puVar3 + 0xc) == '\0') {
    FUN_800614d8(puVar3,(int)param_1);
  }
  if (*(char *)(puVar3 + 0xc) != -1) {
    uVar1 = FUN_800624f4((int)param_1,0x96);
    local_94 = CONCAT31(local_94._0_3_,(char)uVar1);
    if ((uVar1 & 0xff) != 0) {
      pfVar2 = (float *)FUN_8000f56c();
      FUN_8002b554(param_1,&local_50,'\0');
      local_50 = FLOAT_803df8e8;
      local_4c = FLOAT_803df8d8;
      local_48 = FLOAT_803df8d8;
      local_40 = FLOAT_803df8d8;
      local_3c = FLOAT_803df8e8;
      local_38 = FLOAT_803df8d8;
      local_30 = FLOAT_803df8d8;
      local_2c = FLOAT_803df8d8;
      local_28 = FLOAT_803df8e8;
      FUN_80247618(pfVar2,&local_50,afStack_90);
      FUN_8025d80c(afStack_90,0x1b);
      FUN_80257b5c();
      FUN_802570dc(9,1);
      FUN_802570dc(0xd,1);
      FUN_80258944(1);
      FUN_80258674(0,1,4,0x3c,0,0x7d);
      local_98 = local_94;
      FUN_8025c510(0,(byte *)&local_98);
      FUN_8025c5f0(0,0x1c);
      FUN_8025ca04(1);
      FUN_8025be54(0);
      FUN_8025a608(4,0,0,0,0,0,2);
      FUN_8025a608(5,0,0,0,0,0,2);
      FUN_8025a5bc(0);
      FUN_8025c828(0,0,0,0xff);
      FUN_8025be80(0);
      FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
      FUN_8025c224(0,7,6,4,7);
      FUN_8025c2a8(0,0,0,0,1,0);
      FUN_8025c368(0,0,0,0,1,0);
      FUN_8007048c(1,3,0);
      FUN_80259288(0);
      FUN_8025d888(0x1b);
      FUN_8025cce8(1,4,5,5);
      FUN_8004c460(*(int *)(*(int *)(param_1 + 0x32) + 4),0);
      FUN_80259000(0x80,6,4);
      DAT_cc008000._0_2_ = *puVar3;
      DAT_cc008000._0_2_ = puVar3[1];
      DAT_cc008000._0_2_ = puVar3[2];
      DAT_cc008000._0_2_ = 0;
      DAT_cc008000._0_2_ = 0;
      DAT_cc008000._0_2_ = puVar3[3];
      DAT_cc008000._0_2_ = puVar3[4];
      DAT_cc008000._0_2_ = puVar3[5];
      DAT_cc008000._0_2_ = 0x400;
      DAT_cc008000._0_2_ = 0;
      DAT_cc008000._0_2_ = puVar3[6];
      DAT_cc008000._0_2_ = puVar3[7];
      DAT_cc008000._0_2_ = puVar3[8];
      DAT_cc008000._0_2_ = 0x400;
      DAT_cc008000._0_2_ = 0x400;
      DAT_cc008000._0_2_ = puVar3[9];
      DAT_cc008000._0_2_ = puVar3[10];
      DAT_cc008000._0_2_ = puVar3[0xb];
      DAT_cc008000._0_2_ = 0;
      DAT_cc008000._0_2_ = 0x400;
      FUN_8025d888(0);
    }
  }
  return;
}

