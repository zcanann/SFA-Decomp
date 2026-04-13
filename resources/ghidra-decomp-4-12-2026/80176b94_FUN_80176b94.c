// Function: FUN_80176b94
// Entry: 80176b94
// Size: 716 bytes

void FUN_80176b94(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar6 = *(int *)(param_9 + 0xb8);
  *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) & 0xfffd;
  *(byte *)(iVar6 + 0x114) = *(byte *)(iVar6 + 0x114) & 0x7f;
  dVar7 = (double)FLOAT_803e41c0;
  if (dVar7 != (double)*(float *)(param_9 + 0x28)) {
    *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) | 2;
  }
  if ((*(byte *)(iVar6 + 0x114) >> 6 & 1) == 0) {
    iVar2 = FUN_8002bac4();
    bVar4 = FUN_80296434(iVar2);
    if (bVar4 != 0) goto LAB_80176c2c;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  else {
LAB_80176c2c:
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) != 0) && (uVar3 = FUN_80020078(0x913), uVar3 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
    FUN_800201ac(0x913,1);
    return;
  }
  iVar2 = FUN_8002bac4();
  if (((iVar2 != 0) && (uVar3 = FUN_80296164(iVar2,10), uVar3 != 0)) ||
     ((*(ushort *)(iVar6 + 0x100) & 4) != 0)) {
    *(undefined *)(iVar6 + 0x145) = 0x78;
  }
  if (*(char *)(iVar6 + 0x145) == '\0') {
    if (*(char *)(iVar6 + 0x146) != '\0') {
      FUN_800e82d8(param_9);
    }
  }
  else {
    *(char *)(iVar6 + 0x145) = *(char *)(iVar6 + 0x145) + -1;
  }
  sVar1 = *(short *)(param_9 + 0x46);
  if (sVar1 == 0x411) {
    iVar5 = FUN_80174b14(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  else {
    if (0x410 < sVar1) {
      if (sVar1 == 0x54a) {
        uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0xac));
        if (uVar3 != 0) {
          *(float *)(param_9 + 0xc) = (float)((double)*(float *)(iVar5 + 8) - DOUBLE_803e41c8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
          *(float *)(param_9 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar5 + 0x10));
        }
        FUN_801748e4(param_9,iVar6);
      }
      goto LAB_80176e04;
    }
    if (sVar1 != 0x21e) {
      if ((sVar1 < 0x21e) && (sVar1 == 0x108)) {
        if ((FLOAT_803e41c0 == *(float *)(iVar6 + 0xf8)) &&
           (FLOAT_803e41c0 < *(float *)(iVar6 + 0xf4))) {
          FUN_8000bb38(param_9,0x68);
          FUN_800201ac(0x272,1);
        }
        uVar3 = FUN_80020078(0x272);
        if (uVar3 != 0) {
          FUN_8002cf80(param_9);
          FUN_80035ff8(param_9);
          *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        }
      }
      goto LAB_80176e04;
    }
    iVar5 = FUN_80174b14(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  if (iVar5 != 0) {
    return;
  }
LAB_80176e04:
  sVar1 = *(short *)(param_9 + 0x46);
  if (((sVar1 != 0x54a) && (sVar1 != 0x5ae)) &&
     ((sVar1 != 0x108 &&
      ((*(char *)(iVar6 + 0x146) != '\0' && ((*(ushort *)(iVar6 + 0x100) & 8) == 0)))))) {
    FUN_800e85f4(param_9);
  }
  return;
}

