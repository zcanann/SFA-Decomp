// Function: FUN_8005fc74
// Entry: 8005fc74
// Size: 204 bytes

void FUN_8005fc74(int param_1,float *param_2)

{
  float afStack_68 [3];
  float local_5c;
  float local_4c;
  float local_3c;
  float afStack_38 [12];
  
  FUN_8025d80c(param_2,0);
  FUN_802475e4(param_2,afStack_68);
  local_5c = FLOAT_803df84c;
  local_4c = FLOAT_803df84c;
  local_3c = FLOAT_803df84c;
  FUN_8025d848(afStack_68,0);
  FUN_80247618((float *)&DAT_80397450,param_2,afStack_38);
  FUN_8025d8c4(afStack_38,0x24,0);
  FUN_802585d8(9,*(uint *)(param_1 + 0x58),6);
  FUN_802585d8(0xb,*(uint *)(param_1 + 0x5c),2);
  FUN_802585d8(0xd,*(uint *)(param_1 + 0x60),4);
  FUN_802585d8(0xe,*(uint *)(param_1 + 0x60),4);
  return;
}

