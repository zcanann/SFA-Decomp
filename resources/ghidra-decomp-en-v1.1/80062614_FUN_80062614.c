// Function: FUN_80062614
// Entry: 80062614
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x80062824) */
/* WARNING: Removing unreachable block (ram,0x80062624) */

void FUN_80062614(void)

{
  undefined4 uVar1;
  ushort *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  float *pfVar5;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar6;
  undefined4 local_218;
  uint *local_214 [2];
  int local_20c;
  float local_208;
  float local_204;
  undefined4 local_200;
  float local_1fc;
  float local_1f8;
  float local_1f4;
  uint auStack_1f0 [6];
  float afStack_1d8 [24];
  float afStack_178 [76];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_80286840();
  puVar2 = (ushort *)((ulonglong)uVar6 >> 0x20);
  local_20c = 0;
  local_218 = 0;
  puVar3 = (undefined4 *)FUN_80022b0c();
  pfVar5 = *(float **)(puVar2 + 0x32);
  uVar4 = FUN_8005cf38();
  if (uVar4 == 0) {
    *(undefined4 *)(*(int *)(puVar2 + 0x32) + 0xc) = 0;
  }
  else {
    if ((pfVar5[4] == 0.0) || (pfVar5[4] == -NAN)) {
      local_1fc = pfVar5[5];
      local_1f8 = pfVar5[6];
      local_1f4 = pfVar5[7];
      FUN_80061210((double)pfVar5[0xb],&local_1fc,afStack_1d8);
      local_204 = FLOAT_803df8d8;
      if (*(int *)(puVar2 + 0x2a) != 0) {
        uStack_44 = (int)*(short *)(*(int *)(puVar2 + 0x2a) + 0x5e) / 2 ^ 0x80000000;
        local_48 = 0x43300000;
        local_204 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df8e0);
      }
      local_208 = *(float *)(puVar2 + 0xc);
      local_204 = *(float *)(puVar2 + 0xe) + local_204;
      local_200 = *(undefined4 *)(puVar2 + 0x10);
      FUN_80061350((double)*pfVar5,afStack_1d8,&local_208,auStack_1f0);
      FUN_8006933c(puVar2,auStack_1f0,0x81,'\0');
      FUN_80069ad4(local_214);
      FUN_80069ae4(&local_20c,&local_218);
      uVar1 = local_218;
      uStack_3c = *local_214[0] ^ 0x80000000;
      local_40 = 0x43300000;
      uStack_34 = local_214[0][2] ^ 0x80000000;
      local_38 = 0x43300000;
      local_20c = FUN_80060d90((double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                              DOUBLE_803df8e0),
                               (double)(float)((double)CONCAT44(0x43300000,uStack_34) -
                                              DOUBLE_803df8e0),puVar2,local_218,-0x7fc779e4,
                               DAT_803ddbac,local_20c,(int)uVar6,(uint)pfVar5[0xc] & 0x40000);
      DAT_803ddb60 = uVar1;
      DAT_803ddb70 = (undefined2)local_20c;
      DAT_803ddb64 = local_214[0];
      FUN_80061ad0(puVar2,afStack_1d8,afStack_178);
      FUN_80061f54((int)puVar2,afStack_1d8,afStack_178,local_20c,(int)DAT_803ddbac,puVar3,
                   (float *)&DAT_8038861c,0x555);
    }
    FUN_80062088(puVar3,pfVar5,puVar2,(int)DAT_803ddb72);
  }
  FUN_8028688c();
  return;
}

