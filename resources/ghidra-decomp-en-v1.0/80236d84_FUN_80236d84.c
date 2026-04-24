// Function: FUN_80236d84
// Entry: 80236d84
// Size: 524 bytes

/* WARNING: Removing unreachable block (ram,0x80236dc0) */

void FUN_80236d84(int param_1)

{
  short sVar1;
  short sVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(char *)((int)piVar5 + 0x25) == '\x01') {
    cVar3 = FUN_80236298(param_1,piVar5,iVar4);
    if (cVar3 == '\0') {
      if ((*(byte *)(iVar4 + 0x29) & 2) != 0) {
        FUN_8000da58(param_1,(&DAT_8032bd00)[*(byte *)(*(int *)(param_1 + 0x4c) + 0x1b)]);
      }
      iVar4 = *piVar5;
      if (((iVar4 != 0) && (*(char *)(iVar4 + 0x2f8) != '\0')) && (*(char *)(iVar4 + 0x4c) != '\0'))
      {
        sVar1 = (ushort)*(byte *)(iVar4 + 0x2f9) + (short)*(char *)(iVar4 + 0x2fa);
        if (sVar1 < 0) {
          sVar1 = 0;
          *(undefined *)(iVar4 + 0x2fa) = 0;
        }
        else if (0xc < sVar1) {
          sVar2 = FUN_800221a0(0xfffffff4,0xc);
          sVar1 = sVar1 + sVar2;
          if (0xff < sVar1) {
            sVar1 = 0xff;
            *(undefined *)(*piVar5 + 0x2fa) = 0;
          }
        }
        *(char *)(*piVar5 + 0x2f9) = (char)sVar1;
      }
    }
    else {
      *(undefined *)((int)piVar5 + 0x25) = 0;
      if (*piVar5 != 0) {
        FUN_8001db6c((double)FLOAT_803e7374,*piVar5,0);
      }
      if ((*(byte *)(iVar4 + 0x29) & 2) != 0) {
        FUN_8000b7bc(param_1,0x40);
      }
      FUN_80035f00(param_1);
      if (*(short *)(iVar4 + 0x24) != -1) {
        FUN_800200e8((int)*(short *)(iVar4 + 0x24),0);
      }
    }
  }
  else if ((*(char *)((int)piVar5 + 0x25) == '\0') &&
          (cVar3 = FUN_80236388(param_1,piVar5,iVar4), cVar3 != '\0')) {
    *(undefined *)((int)piVar5 + 0x25) = 1;
    if (*piVar5 != 0) {
      FUN_8001db6c((double)FLOAT_803e7374,*piVar5,1);
    }
    if (-1 < *(char *)((int)piVar5 + 0x27)) {
      FUN_80035f20(param_1);
    }
    if (*(short *)(iVar4 + 0x24) != -1) {
      FUN_800200e8((int)*(short *)(iVar4 + 0x24),1);
    }
    *(undefined *)((int)piVar5 + 0x26) = 0xf;
    piVar5[5] = (int)FLOAT_803e7360;
  }
  FUN_8023666c(param_1,piVar5);
  return;
}

