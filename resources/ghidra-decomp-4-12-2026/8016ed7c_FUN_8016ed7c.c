// Function: FUN_8016ed7c
// Entry: 8016ed7c
// Size: 548 bytes

void FUN_8016ed7c(uint param_1)

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
  local_50[0] = DAT_802c29a0;
  local_50[1] = DAT_802c29a4;
  local_50[2] = DAT_802c29a8;
  local_50[3] = DAT_802c29ac;
  local_40 = DAT_802c29b0;
  local_3c = DAT_802c29b4;
  local_38 = DAT_802c29b8;
  local_34 = DAT_802c29bc;
  local_30 = DAT_802c29c0;
  local_2c = DAT_802c29c4;
  local_28 = DAT_802c29c8;
  local_24 = DAT_802c29cc;
  local_20 = DAT_802c29d0;
  local_1c = DAT_802c29d4;
  local_18 = DAT_802c29d8;
  local_14 = DAT_802c29dc;
  FUN_8016e1d8();
  if ((*(char *)(iVar2 + 0xad) != '\0') && (iVar1 = FUN_80020800(), iVar1 == 0)) {
    iVar1 = (int)*(char *)(iVar2 + 0xac);
    if (iVar1 < 0) {
      iVar1 = 0;
    }
    else if (0x23 < iVar1) {
      iVar1 = 0x23;
    }
    if (iVar1 == 0xe) {
      FUN_8000bb00((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,0xba);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)FLOAT_803e3f4c,param_1);
      (**(code **)(*DAT_803dd718 + 0x14))
                ((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                 (double)*(float *)(iVar2 + 0x44),(double)FLOAT_803e3f4c,0,2);
    }
    else {
      local_60 = FLOAT_803e3f20;
      local_64 = 0;
      local_66 = 0;
      local_68 = 0;
      local_5c = *(undefined4 *)(iVar2 + 0x3c);
      local_58 = *(undefined4 *)(iVar2 + 0x40);
      local_54 = *(undefined4 *)(iVar2 + 0x44);
      (**(code **)(*DAT_803de720 + 4))
                (0,1,&local_68,0x401,0xffffffff,local_50 + (uint)(byte)(&DAT_80321538)[iVar1] * 4);
      FUN_8000bb00((double)*(float *)(iVar2 + 0x3c),(double)*(float *)(iVar2 + 0x40),
                   (double)*(float *)(iVar2 + 0x44),param_1,(&DAT_803214f0)[iVar1]);
    }
  }
  return;
}

