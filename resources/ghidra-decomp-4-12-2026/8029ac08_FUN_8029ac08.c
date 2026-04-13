// Function: FUN_8029ac08
// Entry: 8029ac08
// Size: 316 bytes

void FUN_8029ac08(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined8 extraout_f1;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  sVar1 = *(short *)(param_10 + 0x274);
  if ((((sVar1 != 0x2a) && (sVar1 != 0x2e)) && (sVar1 != 0x2f)) && (sVar1 != 0x2c)) {
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
    *(undefined2 *)(iVar3 + 0x80a) = 0xffff;
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfdfffbff;
    if (*(short *)(param_10 + 0x274) != 0x2b) {
      if ((*(char *)(iVar3 + 0x8c8) != 'B') &&
         (iVar2 = FUN_80080490(), param_1 = extraout_f1, iVar2 == 0)) {
        param_1 = (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
      }
      *(byte *)(iVar3 + 0x3f6) = *(byte *)(iVar3 + 0x3f6) & 0xbf;
    }
    DAT_803df0ac = 0;
    iVar3 = 0;
    piVar4 = &DAT_80333b34;
    do {
      if (*piVar4 != 0) {
        param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *piVar4);
        *piVar4 = 0;
      }
      piVar4 = piVar4 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 7);
    if (DAT_803df0d4 != (undefined *)0x0) {
      FUN_80013e4c(DAT_803df0d4);
      DAT_803df0d4 = (undefined *)0x0;
    }
  }
  return;
}

