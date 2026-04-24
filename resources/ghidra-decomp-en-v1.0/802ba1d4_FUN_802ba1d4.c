// Function: FUN_802ba1d4
// Entry: 802ba1d4
// Size: 536 bytes

undefined4 FUN_802ba1d4(int param_1,uint *param_2)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  fVar1 = FLOAT_803e8234;
  param_2[0xa5] = (uint)FLOAT_803e8234;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  iVar2 = FUN_8001ffb4(0x170);
  *(byte *)(param_1 + 0xe4) =
       (byte)((byte)((uint)-iVar2 >> 0x18) | (byte)((uint)iVar2 >> 0x18)) >> 7;
  if ((*(char *)((int)param_2 + 0x27a) != '\0') &&
     (param_2[0xa8] = (uint)FLOAT_803e827c, *(short *)(param_1 + 0xa0) != 0x13)) {
    FUN_80030334((double)FLOAT_803e8234,param_1,0x13,0);
  }
  if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
    iVar2 = (**(code **)(*DAT_803dca68 + 0x20))(0x170);
    if (iVar2 == 0) {
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        iVar2 = FUN_8001ffb4(0x28);
        if (iVar2 == 0) {
          *(undefined *)(iVar4 + 0xa8d) = 1;
        }
        else {
          *(undefined *)(iVar4 + 0xa8d) = 3;
        }
        (**(code **)(*DAT_803dca54 + 0x48))(*(undefined *)(iVar4 + 0xa8d),param_1,0xffffffff);
        FUN_80014b3c(0,0x100);
      }
    }
    else {
      uVar3 = FUN_8001ffb4(0x170);
      uVar3 = uVar3 & 0xff;
      iVar2 = FUN_8001ffb4(0x28);
      if (iVar2 == 0) {
        if (uVar3 == 2) {
          *(undefined *)(iVar4 + 0xa8d) = 4;
          FUN_800200e8(0x16f,1);
        }
        else if ((uVar3 < 2) && (uVar3 != 0)) {
          FUN_800200e8(0x28,1);
          *(undefined *)(iVar4 + 0xa8d) = 2;
        }
      }
      else {
        *(undefined *)(iVar4 + 0xa8d) = 4;
        FUN_800200e8(0x16f,1);
      }
      (**(code **)(*DAT_803dca54 + 0x48))(*(undefined *)(iVar4 + 0xa8d),param_1,0xffffffff);
      iVar2 = FUN_8001ffb4(0x170);
      FUN_800200e8(0x170,iVar2 - uVar3);
      FUN_80014b3c(0,0x100);
    }
  }
  return 0;
}

