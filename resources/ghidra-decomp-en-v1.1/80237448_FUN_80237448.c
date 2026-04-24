// Function: FUN_80237448
// Entry: 80237448
// Size: 524 bytes

/* WARNING: Removing unreachable block (ram,0x80237484) */

void FUN_80237448(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = *(int **)(param_9 + 0xb8);
  iVar3 = *(int *)(param_9 + 0x4c);
  if (*(char *)((int)piVar4 + 0x25) == '\x01') {
    uVar2 = FUN_8023695c(param_9,piVar4,iVar3);
    if ((uVar2 & 0xff) == 0) {
      if ((*(byte *)(iVar3 + 0x29) & 2) != 0) {
        param_1 = FUN_8000da78(param_9,(ushort)(byte)(&DAT_8032c958)
                                                     [*(byte *)(*(int *)(param_9 + 0x4c) + 0x1b)]);
      }
      iVar3 = *piVar4;
      if (((iVar3 != 0) && (*(char *)(iVar3 + 0x2f8) != '\0')) && (*(char *)(iVar3 + 0x4c) != '\0'))
      {
        sVar1 = (ushort)*(byte *)(iVar3 + 0x2f9) + (short)*(char *)(iVar3 + 0x2fa);
        if (sVar1 < 0) {
          sVar1 = 0;
          *(undefined *)(iVar3 + 0x2fa) = 0;
        }
        else if (0xc < sVar1) {
          uVar2 = FUN_80022264(0xfffffff4,0xc);
          sVar1 = sVar1 + (short)uVar2;
          if (0xff < sVar1) {
            sVar1 = 0xff;
            *(undefined *)(*piVar4 + 0x2fa) = 0;
          }
        }
        *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
      }
    }
    else {
      *(undefined *)((int)piVar4 + 0x25) = 0;
      if (*piVar4 != 0) {
        FUN_8001dc30((double)FLOAT_803e800c,*piVar4,'\0');
      }
      if ((*(byte *)(iVar3 + 0x29) & 2) != 0) {
        FUN_8000b7dc(param_9,0x40);
      }
      param_1 = FUN_80035ff8(param_9);
      if ((int)*(short *)(iVar3 + 0x24) != 0xffffffff) {
        param_1 = FUN_800201ac((int)*(short *)(iVar3 + 0x24),0);
      }
    }
  }
  else if ((*(char *)((int)piVar4 + 0x25) == '\0') &&
          (uVar2 = FUN_80236a4c(param_9,piVar4,iVar3), (uVar2 & 0xff) != 0)) {
    *(undefined *)((int)piVar4 + 0x25) = 1;
    if (*piVar4 != 0) {
      param_1 = FUN_8001dc30((double)FLOAT_803e800c,*piVar4,'\x01');
    }
    if (-1 < *(char *)((int)piVar4 + 0x27)) {
      param_1 = FUN_80036018(param_9);
    }
    if ((int)*(short *)(iVar3 + 0x24) != 0xffffffff) {
      param_1 = FUN_800201ac((int)*(short *)(iVar3 + 0x24),1);
    }
    *(undefined *)((int)piVar4 + 0x26) = 0xf;
    piVar4[5] = (int)FLOAT_803e7ff8;
  }
  FUN_80236d30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

