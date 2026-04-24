// Function: FUN_8029d028
// Entry: 8029d028
// Size: 256 bytes

void FUN_8029d028(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  dVar4 = (double)*(float *)(param_10 + 0x298);
  if ((double)FLOAT_803e8c04 <= dVar4) {
    *(undefined4 *)(iVar2 + 0x494) = *(undefined4 *)(iVar2 + 0x474);
    *(short *)(iVar2 + 0x484) = (short)*(undefined4 *)(iVar2 + 0x474);
    *(undefined4 *)(iVar2 + 0x48c) = 0;
    *(undefined4 *)(iVar2 + 0x488) = 0;
  }
  else {
    sVar1 = *param_9;
    *(short *)(iVar2 + 0x484) = sVar1;
    *(short *)(iVar2 + 0x478) = sVar1;
    *(int *)(iVar2 + 0x494) = (int)sVar1;
    *(float *)(param_10 + 0x298) = FLOAT_803e8b3c;
  }
  DAT_803dd2d4 = 1;
  if (((*(short *)(param_10 + 0x274) != 0x24) && (*(short *)(param_10 + 0x274) != 0x25)) &&
     (DAT_803df0ac != '\0')) {
    *(undefined2 *)(iVar2 + 0x80a) = 0xffff;
    DAT_803df0ac = '\0';
    iVar2 = 0;
    piVar3 = &DAT_80333b34;
    do {
      if (*piVar3 != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     *piVar3);
        *piVar3 = 0;
      }
      piVar3 = piVar3 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 7);
    if (DAT_803df0d4 != (undefined *)0x0) {
      FUN_80013e4c(DAT_803df0d4);
      DAT_803df0d4 = (undefined *)0x0;
    }
  }
  return;
}

