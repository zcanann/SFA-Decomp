// Function: FUN_8001cc9c
// Entry: 8001cc9c
// Size: 272 bytes

void FUN_8001cc9c(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
                 uint param_5)

{
  undefined extraout_r4;
  uint uVar1;
  int iVar2;
  
  FUN_802860dc();
  if (DAT_803dca30 < 0x32) {
    iVar2 = FUN_8001de4c();
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      uVar1 = (uint)DAT_803dca30;
      DAT_803dca30 = DAT_803dca30 + 1;
      (&DAT_8033bec0)[uVar1] = iVar2;
    }
  }
  else {
    iVar2 = 0;
  }
  if (iVar2 != 0) {
    *(undefined4 *)(iVar2 + 0x50) = 2;
    *(undefined *)(iVar2 + 0xac) = extraout_r4;
    *(undefined *)(iVar2 + 0xa8) = extraout_r4;
    *(undefined *)(iVar2 + 0xad) = param_3;
    *(undefined *)(iVar2 + 0xa9) = param_3;
    *(undefined *)(iVar2 + 0xae) = param_4;
    *(undefined *)(iVar2 + 0xaa) = param_4;
    *(undefined *)(iVar2 + 0xaf) = 0;
    *(undefined *)(iVar2 + 0xab) = 0;
    *(undefined *)(iVar2 + 0xbc) = 1;
    *(float *)(iVar2 + 0x140) = FLOAT_803de750;
    *(float *)(iVar2 + 0x144) = FLOAT_803de754;
    FUN_80259848((double)*(float *)(iVar2 + 0x140),(double)FLOAT_803de758,iVar2 + 0x68,2);
    FUN_802596ac(iVar2 + 0x68,iVar2 + 0x124,iVar2 + 0x128,iVar2 + 300);
    if ((param_5 & 0xff) != 0) {
      *(undefined *)(iVar2 + 0x2fb) = 1;
    }
  }
  FUN_80286128(iVar2);
  return;
}

