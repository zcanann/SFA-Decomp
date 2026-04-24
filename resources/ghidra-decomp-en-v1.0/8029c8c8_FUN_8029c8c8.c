// Function: FUN_8029c8c8
// Entry: 8029c8c8
// Size: 256 bytes

void FUN_8029c8c8(short *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  if (FLOAT_803e7f6c <= *(float *)(param_2 + 0x298)) {
    *(undefined4 *)(iVar2 + 0x494) = *(undefined4 *)(iVar2 + 0x474);
    *(short *)(iVar2 + 0x484) = (short)*(undefined4 *)(iVar2 + 0x474);
    *(undefined4 *)(iVar2 + 0x48c) = 0;
    *(undefined4 *)(iVar2 + 0x488) = 0;
  }
  else {
    sVar1 = *param_1;
    *(short *)(iVar2 + 0x484) = sVar1;
    *(short *)(iVar2 + 0x478) = sVar1;
    *(int *)(iVar2 + 0x494) = (int)sVar1;
    *(float *)(param_2 + 0x298) = FLOAT_803e7ea4;
  }
  DAT_803dc66c = 1;
  if (((*(short *)(param_2 + 0x274) != 0x24) && (*(short *)(param_2 + 0x274) != 0x25)) &&
     (DAT_803de42c != '\0')) {
    *(undefined2 *)(iVar2 + 0x80a) = 0xffff;
    DAT_803de42c = '\0';
    iVar2 = 0;
    piVar3 = &DAT_80332ed4;
    do {
      if (*piVar3 != 0) {
        FUN_8002cbc4();
        *piVar3 = 0;
      }
      piVar3 = piVar3 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 7);
    if (DAT_803de454 != 0) {
      FUN_80013e2c();
      DAT_803de454 = 0;
    }
  }
  return;
}

