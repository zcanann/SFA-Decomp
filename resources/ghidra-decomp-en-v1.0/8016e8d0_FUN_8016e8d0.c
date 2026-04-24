// Function: FUN_8016e8d0
// Entry: 8016e8d0
// Size: 548 bytes

void FUN_8016e8d0(int param_1)

{
  int iVar1;
  int iVar2;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50 [4];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar2 = *(int *)(param_1 + 0x54);
  local_50[0] = DAT_802c2220;
  local_50[1] = DAT_802c2224;
  local_50[2] = DAT_802c2228;
  local_50[3] = DAT_802c222c;
  local_40 = DAT_802c2230;
  local_3c = DAT_802c2234;
  local_38 = DAT_802c2238;
  local_34 = DAT_802c223c;
  local_30 = DAT_802c2240;
  local_2c = DAT_802c2244;
  local_28 = DAT_802c2248;
  local_24 = DAT_802c224c;
  local_20 = DAT_802c2250;
  local_1c = DAT_802c2254;
  local_18 = DAT_802c2258;
  local_14 = DAT_802c225c;
  FUN_8016dd2c(param_1,*(undefined4 *)(param_1 + 0xb8));
  if ((*(char *)(iVar2 + 0xad) != '\0') && (iVar1 = FUN_8002073c(), iVar1 == 0)) {
    iVar1 = (int)*(char *)(iVar2 + 0xac);
    if (iVar1 < 0) {
      iVar1 = 0;
    }
    else if (0x23 < iVar1) {
      iVar1 = 0x23;
    }
    if (iVar1 == 0xe) {
      FUN_8000bae0((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,0xba);
      (**(code **)(*DAT_803dca98 + 0x10))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)FLOAT_803e32b4,param_1);
      (**(code **)(*DAT_803dca98 + 0x14))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)FLOAT_803e32b4,0,2);
    }
    else {
      local_60 = FLOAT_803e3288;
      local_64 = 0;
      local_66 = 0;
      local_68 = 0;
      local_5c = *(undefined4 *)(iVar2 + 0x3c);
      local_58 = *(undefined4 *)(iVar2 + 0x40);
      local_54 = *(undefined4 *)(iVar2 + 0x44);
      (**(code **)(*DAT_803ddaa0 + 4))
                (0,1,&local_68,0x401,0xffffffff,local_50 + (uint)(byte)(&DAT_803208e8)[iVar1] * 4);
      FUN_8000bae0((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,(&DAT_803208a0)[iVar1]);
    }
  }
  return;
}

