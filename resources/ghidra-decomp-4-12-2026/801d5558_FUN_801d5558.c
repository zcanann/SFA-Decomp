// Function: FUN_801d5558
// Entry: 801d5558
// Size: 524 bytes

uint FUN_801d5558(short *param_1,int param_2,int param_3)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  
  if (*(char *)(param_3 + 0x1b) == '\0') {
    uVar3 = 7;
  }
  else {
    iVar2 = FUN_8002bac4();
    dVar4 = FUN_80021730((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e60bc <= dVar4) {
      dVar4 = FUN_80021730((float *)(param_1 + 0xc),(float *)(param_3 + 8));
      if ((double)(float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(param_3 + 0x1b) *
                                           (uint)*(byte *)(param_3 + 0x1b) ^ 0x80000000) -
                         DOUBLE_803e60c0) < dVar4) {
        iVar2 = FUN_80021884();
        sVar1 = (short)iVar2 - *param_1;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        iVar2 = (int)sVar1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
        }
        if (0x20 < iVar2) {
          FUN_80021884();
          FUN_8007d858();
          if (('\x01' < *(char *)(param_2 + 0x624)) && (*(char *)(param_2 + 0x624) < '\x06')) {
            return 6;
          }
          return 7;
        }
      }
      iVar2 = FUN_8005a288((double)(*(float *)(param_1 + 0x54) * *(float *)(param_1 + 4)),
                           (float *)(param_1 + 6));
      if (iVar2 == 0) {
        uVar3 = 7;
      }
      else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
        uVar3 = 2;
      }
      else {
        uVar3 = FUN_80022264(3,5);
        uVar3 = uVar3 & 0xff;
      }
    }
    else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
      uVar3 = 7;
    }
    else {
      uVar3 = 6;
    }
  }
  return uVar3;
}

