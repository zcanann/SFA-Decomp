// Function: FUN_80158368
// Entry: 80158368
// Size: 1496 bytes

void FUN_80158368(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined *puVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  uVar5 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar7 = (&PTR_DAT_8032074c)[uVar5 * 8];
  iVar6 = param_14;
  if (param_12 == 0xe) {
    iVar6 = param_14 << 3;
  }
  if ((uVar5 == 0) && (param_12 == 5)) {
    iVar6 = iVar6 << 2;
  }
  if ((uVar5 == 1) &&
     (((*(short *)(param_11 + 0x46) == 0x1b5 || (*(short *)(param_11 + 0x44) == 0x1c)) ||
      (param_12 == 0x1f)))) goto LAB_80158928;
  if (((*(byte *)(iVar4 + 0x33c) & 4) == 0) &&
     ((uVar5 != 0 || ((*(byte *)(iVar4 + 0x2f1) & 0x40) == 0)))) {
    if ((uVar5 == 1) && (*(int *)(uVar3 + 200) != 0)) {
      FUN_80220104(*(int *)(uVar3 + 200));
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xbf;
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
    if ((param_12 == 0x10) && (*(char *)(iVar4 + 0x33b) != '\0')) {
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x20;
      goto LAB_80158928;
    }
    if (*(char *)(iVar4 + 0x33f) == '\0') {
      if ((((*(char *)(iVar4 + 0x33b) != '\0') || (param_12 != 0x11)) ||
          (uVar5 = FUN_80020078(0xc55), uVar5 == 0)) && (*(char *)(iVar4 + 0x33b) != '\x01')) {
        if (param_12 != 0x11) {
          if (*(short *)(uVar3 + 0x46) == 0x6a2) {
            if ((FLOAT_803de6f0 <= FLOAT_803e3840) && (param_11 != 0)) {
              sVar1 = *(short *)(param_11 + 0x46);
              if (sVar1 == 0x69) {
LAB_801588ec:
                FUN_8000bb38(uVar3,0x22);
              }
              else if (sVar1 < 0x69) {
                if (sVar1 == 0) goto LAB_801588ec;
              }
              else if (sVar1 == 0x416) {
                FUN_8000bb38(uVar3,0x36e);
              }
              FUN_8000bb38(uVar3,0x4aa);
              FLOAT_803de6f0 = FLOAT_803e3844;
            }
          }
          else {
            FUN_8000bb38(uVar3,0x23e);
          }
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_80158928;
      }
      FUN_8014d504((double)*(float *)(puVar7 + 0x10),param_2,param_3,param_4,param_5,param_6,param_7
                   ,param_8,uVar3,iVar4,(uint)(byte)puVar7[0x18],0,*(uint *)(puVar7 + 0x14) & 0xff,
                   param_14,param_15,param_16);
      *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar7 + 0x1c);
      *(byte *)(uVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar7[0x19];
      if (*(char *)(iVar4 + 0x33b) != '\0') {
        if (*(char *)(iVar4 + 0x33b) != '\x01') goto LAB_80158928;
        *(float *)(iVar4 + 0x328) =
             FLOAT_803e384c *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e3828
                    );
        if (*(short *)(uVar3 + 0x46) == 0x6a2) {
          if ((FLOAT_803de6f0 <= FLOAT_803e3840) && (param_11 != 0)) {
            sVar1 = *(short *)(param_11 + 0x46);
            if (sVar1 == 0x69) {
LAB_80158844:
              FUN_8000bb38(uVar3,0x22);
            }
            else if (sVar1 < 0x69) {
              if (sVar1 == 0) goto LAB_80158844;
            }
            else if (sVar1 == 0x416) {
              FUN_8000bb38(uVar3,0x36e);
            }
            FUN_8000bb38(uVar3,0x4aa);
            FLOAT_803de6f0 = FLOAT_803e3844;
          }
        }
        else {
          FUN_8000bb38(uVar3,0x23e);
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_80158928;
      }
      *(float *)(iVar4 + 0x328) =
           FLOAT_803e3848 *
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e3828);
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
      if (*(short *)(uVar3 + 0x46) != 0x6a2) {
        FUN_8000bb38(uVar3,0x23f);
        goto LAB_80158928;
      }
      if ((FLOAT_803e3840 < FLOAT_803de6f0) || (param_11 == 0)) goto LAB_80158928;
      sVar1 = *(short *)(param_11 + 0x46);
      if (sVar1 == 0x69) {
LAB_80158780:
        FUN_8000bb38(uVar3,0x22);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_80158780;
      }
      else if (sVar1 == 0x416) {
        FUN_8000bb38(uVar3,0x36e);
      }
      FUN_8000bb38(uVar3,0x4aa);
      FLOAT_803de6f0 = FLOAT_803e3844;
      goto LAB_80158928;
    }
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      iVar2 = 4;
    }
    else {
      iVar2 = 3;
    }
    iVar2 = iVar2 * 0x10;
    FUN_8014d504((double)*(float *)(puVar7 + iVar2),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,uVar3,iVar4,(uint)(byte)puVar7[iVar2 + 8],0,
                 *(uint *)(puVar7 + iVar2 + 4) & 0xff,param_14,param_15,param_16);
    *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar7 + iVar2 + 0xc);
    *(byte *)(uVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar7[iVar2 + 9];
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
    if (*(short *)(uVar3 + 0x46) == 0x6a2) {
      if ((FLOAT_803de6f0 <= FLOAT_803e3840) && (param_11 != 0)) {
        sVar1 = *(short *)(param_11 + 0x46);
        if (sVar1 == 0x69) {
LAB_801585f4:
          FUN_8000bb38(uVar3,0x22);
        }
        else if (sVar1 < 0x69) {
          if (sVar1 == 0) goto LAB_801585f4;
        }
        else if (sVar1 == 0x416) {
          FUN_8000bb38(uVar3,0x36e);
        }
        FUN_8000bb38(uVar3,0x4aa);
        FLOAT_803de6f0 = FLOAT_803e3844;
      }
    }
    else {
      FUN_8000bb38(uVar3,0x23f);
    }
    if ((int)(uint)*(ushort *)(iVar4 + 0x2b0) < iVar6) {
      *(undefined2 *)(iVar4 + 0x2b0) = 0;
    }
    else {
      *(ushort *)(iVar4 + 0x2b0) = *(ushort *)(iVar4 + 0x2b0) - (short)iVar6;
    }
    if ((*(short *)(iVar4 + 0x2b0) == 0) && (*(char *)(iVar4 + 0x33b) == '\0')) {
      FUN_80157e34(uVar3);
    }
    goto LAB_80158928;
  }
  if (param_12 == 0x11) goto LAB_80158928;
  if (*(short *)(uVar3 + 0x46) == 0x6a2) {
    if ((FLOAT_803de6f0 <= FLOAT_803e3840) && (param_11 != 0)) {
      sVar1 = *(short *)(param_11 + 0x46);
      if (sVar1 == 0x69) {
LAB_80158484:
        FUN_8000bb38(uVar3,0x22);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_80158484;
      }
      else if (sVar1 == 0x416) {
        FUN_8000bb38(uVar3,0x36e);
      }
      FLOAT_803de6f0 = FLOAT_803e3844;
    }
  }
  else {
    FUN_8000bb38(uVar3,0x23e);
  }
  *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
LAB_80158928:
  FUN_80286888();
  return;
}

