// Function: FUN_801f3ae4
// Entry: 801f3ae4
// Size: 800 bytes

void FUN_801f3ae4(uint param_1)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [8];
  float local_24;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  if (*(char *)(piVar4 + 5) == '\x01') {
    *(undefined *)(piVar4 + 6) = *(undefined *)((int)piVar4 + 0x17);
    iVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if (iVar2 != 0) {
      *(char *)((int)piVar4 + 0x17) = '\x01' - *(char *)((int)piVar4 + 0x17);
    }
    if (*(char *)((int)piVar4 + 0x17) != *(char *)(piVar4 + 6)) {
      if (*(char *)((int)piVar4 + 0x17) == '\0') {
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((piVar4[4] != 0xffffffff) && (uVar3 = FUN_80020078(piVar4[4]), uVar3 != 0)) {
          FUN_800201ac(piVar4[4],0);
        }
      }
      else {
        if ((piVar4[4] != 0xffffffff) && (uVar3 = FUN_80020078(piVar4[4]), uVar3 == 0)) {
          FUN_800201ac(piVar4[4],1);
        }
        FUN_8000bb38(param_1,0x80);
      }
    }
  }
  if ((*(char *)((int)piVar4 + 0x17) != '\0') && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    piVar4[1] = (int)((float)piVar4[1] - FLOAT_803dc074);
    if (FLOAT_803e6aa4 < (float)piVar4[1]) {
      uVar3 = 0;
    }
    else {
      uVar3 = (uint)*(byte *)((int)piVar4 + 0x16);
      piVar4[1] = (int)((float)piVar4[1] + FLOAT_803e6aa8);
    }
    if ((*(char *)((int)piVar4 + 0x15) != '\0') || (*(char *)((int)piVar4 + 0x16) != '\0')) {
      local_38 = FLOAT_803e6aa4;
      if (*(short *)(param_1 + 0x46) == 0x717) {
        local_34 = FLOAT_803e6aa4;
      }
      else {
        local_34 = FLOAT_803e6aac;
      }
      local_30 = FLOAT_803e6aa4;
      FUN_80098da4(param_1,(uint)*(byte *)((int)piVar4 + 0x15),uVar3,0,&local_38);
    }
    if ((*(char *)((int)piVar4 + 0x19) != '\0') &&
       (piVar4[3] = (int)((float)piVar4[3] - FLOAT_803dc074), (float)piVar4[3] <= FLOAT_803e6aa4)) {
      local_24 = FLOAT_803e6aa0;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7cb,auStack_2c,2,0xffffffff,0);
      piVar4[3] = (int)((float)piVar4[3] + FLOAT_803e6ab4);
    }
  }
  iVar2 = *piVar4;
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    sVar1 = (ushort)*(byte *)(iVar2 + 0x2f9) + (short)*(char *)(iVar2 + 0x2fa);
    if (sVar1 < 0) {
      sVar1 = 0;
      *(undefined *)(iVar2 + 0x2fa) = 0;
    }
    else if (0xff < sVar1) {
      sVar1 = 0xff;
      *(undefined *)(iVar2 + 0x2fa) = 0;
    }
    *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
  }
  if ((*(short *)(param_1 + 0x46) != 0x705) && (*(short *)(param_1 + 0x46) != 0x712)) {
    if (*(char *)((int)piVar4 + 0x17) == '\0') {
      if (*(char *)((int)piVar4 + 0x1a) < '\0') {
        FUN_8000dbb0();
        *(byte *)((int)piVar4 + 0x1a) = *(byte *)((int)piVar4 + 0x1a) & 0x7f;
      }
    }
    else if (-1 < *(char *)((int)piVar4 + 0x1a)) {
      FUN_8000dcdc(param_1,0x72);
      *(byte *)((int)piVar4 + 0x1a) = *(byte *)((int)piVar4 + 0x1a) & 0x7f | 0x80;
    }
  }
  return;
}

