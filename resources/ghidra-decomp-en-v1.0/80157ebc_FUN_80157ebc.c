// Function: FUN_80157ebc
// Entry: 80157ebc
// Size: 1496 bytes

void FUN_80157ebc(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,
                 int param_6)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  uVar5 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar6 = (&PTR_DAT_8031fafc)[uVar5 * 8];
  if (param_4 == 0xe) {
    param_6 = param_6 << 3;
  }
  if ((uVar5 == 0) && (param_4 == 5)) {
    param_6 = param_6 << 2;
  }
  if ((uVar5 == 1) &&
     (((*(short *)(param_3 + 0x46) == 0x1b5 || (*(short *)(param_3 + 0x44) == 0x1c)) ||
      (param_4 == 0x1f)))) goto LAB_8015847c;
  if (((*(byte *)(iVar4 + 0x33c) & 4) == 0) &&
     ((uVar5 != 0 || ((*(byte *)(iVar4 + 0x2f1) & 0x40) == 0)))) {
    if ((uVar5 == 1) && (*(int *)(iVar3 + 200) != 0)) {
      FUN_8021fab4();
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xbf;
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
    if ((param_4 == 0x10) && (*(char *)(iVar4 + 0x33b) != '\0')) {
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x20;
      goto LAB_8015847c;
    }
    if (*(char *)(iVar4 + 0x33f) == '\0') {
      if ((((*(char *)(iVar4 + 0x33b) != '\0') || (param_4 != 0x11)) ||
          (iVar2 = FUN_8001ffb4(0xc55), iVar2 == 0)) && (*(char *)(iVar4 + 0x33b) != '\x01')) {
        if (param_4 != 0x11) {
          if (*(short *)(iVar3 + 0x46) == 0x6a2) {
            if ((FLOAT_803dda70 <= FLOAT_803e2ba8) && (param_3 != 0)) {
              sVar1 = *(short *)(param_3 + 0x46);
              if (sVar1 == 0x69) {
LAB_80158440:
                FUN_8000bb18(iVar3,0x22);
              }
              else if (sVar1 < 0x69) {
                if (sVar1 == 0) goto LAB_80158440;
              }
              else if (sVar1 == 0x416) {
                FUN_8000bb18(iVar3,0x36e);
              }
              FUN_8000bb18(iVar3,0x4aa);
              FLOAT_803dda70 = FLOAT_803e2bac;
            }
          }
          else {
            FUN_8000bb18(iVar3,0x23e);
          }
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_8015847c;
      }
      FUN_8014d08c((double)*(float *)(puVar6 + 0x10),iVar3,iVar4,puVar6[0x18],0,
                   *(uint *)(puVar6 + 0x14) & 0xff);
      *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar6 + 0x1c);
      *(byte *)(iVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar6[0x19];
      if (*(char *)(iVar4 + 0x33b) != '\0') {
        if (*(char *)(iVar4 + 0x33b) != '\x01') goto LAB_8015847c;
        *(float *)(iVar4 + 0x328) =
             FLOAT_803e2bb4 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e2b90
                    );
        if (*(short *)(iVar3 + 0x46) == 0x6a2) {
          if ((FLOAT_803dda70 <= FLOAT_803e2ba8) && (param_3 != 0)) {
            sVar1 = *(short *)(param_3 + 0x46);
            if (sVar1 == 0x69) {
LAB_80158398:
              FUN_8000bb18(iVar3,0x22);
            }
            else if (sVar1 < 0x69) {
              if (sVar1 == 0) goto LAB_80158398;
            }
            else if (sVar1 == 0x416) {
              FUN_8000bb18(iVar3,0x36e);
            }
            FUN_8000bb18(iVar3,0x4aa);
            FLOAT_803dda70 = FLOAT_803e2bac;
          }
        }
        else {
          FUN_8000bb18(iVar3,0x23e);
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_8015847c;
      }
      *(float *)(iVar4 + 0x328) =
           FLOAT_803e2bb0 *
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e2b90);
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
      if (*(short *)(iVar3 + 0x46) != 0x6a2) {
        FUN_8000bb18(iVar3,0x23f);
        goto LAB_8015847c;
      }
      if ((FLOAT_803e2ba8 < FLOAT_803dda70) || (param_3 == 0)) goto LAB_8015847c;
      sVar1 = *(short *)(param_3 + 0x46);
      if (sVar1 == 0x69) {
LAB_801582d4:
        FUN_8000bb18(iVar3,0x22);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_801582d4;
      }
      else if (sVar1 == 0x416) {
        FUN_8000bb18(iVar3,0x36e);
      }
      FUN_8000bb18(iVar3,0x4aa);
      FLOAT_803dda70 = FLOAT_803e2bac;
      goto LAB_8015847c;
    }
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      iVar2 = 4;
    }
    else {
      iVar2 = 3;
    }
    iVar2 = iVar2 * 0x10;
    FUN_8014d08c((double)*(float *)(puVar6 + iVar2),iVar3,iVar4,puVar6[iVar2 + 8],0,
                 *(uint *)(puVar6 + iVar2 + 4) & 0xff);
    *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar6 + iVar2 + 0xc);
    *(byte *)(iVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar6[iVar2 + 9];
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
    if (*(short *)(iVar3 + 0x46) == 0x6a2) {
      if ((FLOAT_803dda70 <= FLOAT_803e2ba8) && (param_3 != 0)) {
        sVar1 = *(short *)(param_3 + 0x46);
        if (sVar1 == 0x69) {
LAB_80158148:
          FUN_8000bb18(iVar3,0x22);
        }
        else if (sVar1 < 0x69) {
          if (sVar1 == 0) goto LAB_80158148;
        }
        else if (sVar1 == 0x416) {
          FUN_8000bb18(iVar3,0x36e);
        }
        FUN_8000bb18(iVar3,0x4aa);
        FLOAT_803dda70 = FLOAT_803e2bac;
      }
    }
    else {
      FUN_8000bb18(iVar3,0x23f);
    }
    if ((int)(uint)*(ushort *)(iVar4 + 0x2b0) < param_6) {
      *(undefined2 *)(iVar4 + 0x2b0) = 0;
    }
    else {
      *(ushort *)(iVar4 + 0x2b0) = *(ushort *)(iVar4 + 0x2b0) - (short)param_6;
    }
    if ((*(short *)(iVar4 + 0x2b0) == 0) && (*(char *)(iVar4 + 0x33b) == '\0')) {
      FUN_80157988(iVar3,iVar4);
    }
    goto LAB_8015847c;
  }
  if (param_4 == 0x11) goto LAB_8015847c;
  if (*(short *)(iVar3 + 0x46) == 0x6a2) {
    if ((FLOAT_803dda70 <= FLOAT_803e2ba8) && (param_3 != 0)) {
      sVar1 = *(short *)(param_3 + 0x46);
      if (sVar1 == 0x69) {
LAB_80157fd8:
        FUN_8000bb18(iVar3,0x22);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_80157fd8;
      }
      else if (sVar1 == 0x416) {
        FUN_8000bb18(iVar3,0x36e);
      }
      FLOAT_803dda70 = FLOAT_803e2bac;
    }
  }
  else {
    FUN_8000bb18(iVar3,0x23e);
  }
  *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
LAB_8015847c:
  FUN_80286124();
  return;
}

