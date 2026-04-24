// Function: FUN_800a0010
// Entry: 800a0010
// Size: 336 bytes

void FUN_800a0010(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7)

{
  int iVar1;
  
  DAT_8039be98 = &DAT_8039bef8;
  iVar1 = (DAT_803dd28c - DAT_803dd290) / 0x18 + (DAT_803dd28c - DAT_803dd290 >> 0x1f);
  DAT_8039bef5 = (char)iVar1 - (char)(iVar1 >> 0x1f);
  if ((param_7 == 0) && (param_6 == 0)) {
    DAT_8039beec = DAT_8039beec | 0x2000000;
  }
  else {
    DAT_8039beec = DAT_8039beec | 0x4000000;
  }
  if ((DAT_8039beec & 1) != 0) {
    if (DAT_8039be9c == 0) {
      DAT_8039bec4 = DAT_8039bec4 + *(float *)(param_1 + 0xc);
      DAT_8039bec8 = DAT_8039bec8 + *(float *)(param_1 + 0x10);
      DAT_8039becc = DAT_8039becc + *(float *)(param_1 + 0x14);
    }
    else {
      DAT_8039bec4 = DAT_8039bec4 + *(float *)(DAT_8039be9c + 0x18);
      DAT_8039bec8 = DAT_8039bec8 + *(float *)(DAT_8039be9c + 0x1c);
      DAT_8039becc = DAT_8039becc + *(float *)(DAT_8039be9c + 0x20);
    }
  }
  DAT_803dd288 = FUN_800a2e5c(&DAT_8039be98,0,param_3,param_2,param_5,param_4,param_6);
  return;
}

