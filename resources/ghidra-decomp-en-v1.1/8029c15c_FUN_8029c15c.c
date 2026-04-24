// Function: FUN_8029c15c
// Entry: 8029c15c
// Size: 524 bytes

int FUN_8029c15c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)

{
  int iVar1;
  ushort uVar2;
  undefined *puVar3;
  undefined *puVar4;
  
  puVar4 = *(undefined **)(param_9 + 0x5c);
  if ((*(char *)(param_10 + 0x349) == '\x01') || (*(short *)(param_10 + 0x274) == 0x26)) {
    puVar3 = puVar4;
    iVar1 = FUN_802acf3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_10,(int)puVar4,param_12,param_13,param_14,param_15,param_16);
    if (iVar1 == 0) {
      if ((*(short *)(param_10 + 0x274) == 0x26) || (((byte)puVar4[0x3f6] >> 5 & 1) != 0)) {
        iVar1 = 0;
      }
      else if ((*(short *)(param_10 + 0x274) == 0x39) ||
              (uVar2 = FUN_80014e04(0), (uVar2 & 0x20) == 0)) {
        if (*(short *)(param_10 + 0x274) == 0x39) {
          iVar1 = 0;
        }
        else {
          if ((((*(uint *)(param_10 + 0x31c) & 0x100) != 0) && (DAT_803df0cc != 0)) &&
             (((byte)puVar4[0x3f4] >> 6 & 1) != 0)) {
            puVar4[0x8b4] = 4;
            puVar4[0x3f4] = puVar4[0x3f4] & 0xf7 | 8;
          }
          iVar1 = FUN_8029a5a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               param_9,param_10,puVar3,param_12,param_13,param_14,param_15,param_16)
          ;
          if (iVar1 == 0) {
            iVar1 = 0;
          }
        }
      }
      else {
        puVar4[0x3f6] = puVar4[0x3f6] & 0xdf | 0x20;
        *(undefined **)(param_10 + 0x308) = &LAB_80297f8c;
        iVar1 = 0x3a;
      }
    }
    else {
      if ((DAT_803df0cc != 0) && (((byte)puVar4[0x3f4] >> 6 & 1) != 0)) {
        puVar4[0x8b4] = 1;
        puVar4[0x3f4] = puVar4[0x3f4] & 0xf7 | 8;
      }
      *(undefined4 *)(param_10 + 0x2d0) = 0;
      *(undefined *)(param_10 + 0x349) = 0;
      (**(code **)(*DAT_803dd6d0 + 0x48))(0);
    }
  }
  else {
    if ((DAT_803df0cc != 0) && (((byte)puVar4[0x3f4] >> 6 & 1) != 0)) {
      puVar4[0x8b4] = 0;
      puVar4[0x3f4] = puVar4[0x3f4] & 0xf7;
    }
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    iVar1 = 2;
  }
  return iVar1;
}

