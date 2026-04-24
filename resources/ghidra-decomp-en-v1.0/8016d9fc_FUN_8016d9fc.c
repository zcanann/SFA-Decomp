// Function: FUN_8016d9fc
// Entry: 8016d9fc
// Size: 504 bytes

void FUN_8016d9fc(undefined4 *param_1)

{
  int iVar1;
  char cVar3;
  int iVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  undefined4 local_1c;
  float local_18;
  undefined4 local_14;
  
  if (DAT_803ac6d8 != '\0') {
    FUN_8002cbc4(DAT_803ac6d4);
    DAT_803ac6d4 = 0;
  }
  DAT_803ac6b8 = *param_1;
  DAT_803ac6bc = (float)((double)FLOAT_803e32a8 + (double)(float)param_1[1]);
  DAT_803ac6c0 = param_1[2];
  DAT_803ac6d0 = FLOAT_803e32f4;
  DAT_803ac6c4 = FLOAT_803e3288;
  DAT_803ac6c8 = FLOAT_803e3290;
  DAT_803ac6cc = FLOAT_803e3288;
  FUN_8000e650((double)FLOAT_803e32f8,(double)FLOAT_803e32a8,(double)FLOAT_803e32fc);
  iVar1 = FUN_8002b9ec();
  if ((iVar1 != 0) && (cVar3 = FUN_8002e04c(), cVar3 != '\0')) {
    DAT_803ac6d8 = '\x01';
    local_1c = DAT_803ac6b8;
    local_18 = DAT_803ac6bc;
    local_14 = DAT_803ac6c0;
    local_20 = FLOAT_803e3288;
    local_28 = 0;
    local_24 = 0;
    local_26 = 0;
    (**(code **)(*DAT_803dca88 + 8))(iVar1,0x565,&local_28,0x200000,0xffffffff,0);
    iVar2 = FUN_8002bdf4(0x24,0x63c);
    *(undefined *)(iVar2 + 4) = 1;
    *(undefined *)(iVar2 + 6) = 0xff;
    *(undefined *)(iVar2 + 5) = 2;
    *(undefined *)(iVar2 + 7) = 0xff;
    *(undefined4 *)(iVar2 + 8) = DAT_803ac6b8;
    *(float *)(iVar2 + 0xc) = DAT_803ac6bc;
    *(undefined4 *)(iVar2 + 0x10) = DAT_803ac6c0;
    DAT_803ac6d4 = FUN_8002df90(iVar2,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                                *(undefined4 *)(iVar1 + 0x30));
    iVar1 = FUN_8001ffb4(0xc55);
    if (iVar1 != 0) {
      *(undefined *)(DAT_803ac6d4 + 0xad) = 1;
    }
    FUN_80035974(DAT_803ac6d4,1);
    FUN_80035df4(DAT_803ac6d4,0x11,5,0);
    *(float *)(DAT_803ac6d4 + 8) = FLOAT_803e32d0;
    *(undefined *)(DAT_803ac6d4 + 0x36) = 0xff;
  }
  return;
}

