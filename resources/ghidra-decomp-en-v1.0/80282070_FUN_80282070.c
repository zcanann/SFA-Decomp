// Function: FUN_80282070
// Entry: 80282070
// Size: 1160 bytes

/* WARNING: Removing unreachable block (ram,0x802823b8) */
/* WARNING: Removing unreachable block (ram,0x802821b4) */

uint FUN_80282070(int param_1,byte *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  byte bVar2;
  short sVar4;
  uint uVar3;
  uint extraout_r4;
  uint uVar5;
  uint uVar6;
  int unaff_r29;
  byte *pbVar7;
  
  uVar5 = 0;
  uVar6 = 0;
  pbVar7 = param_2;
  do {
    if (param_2[0x22] <= uVar6) {
      *(short *)(param_2 + 0x20) = (short)uVar5;
      return uVar5 & 0xffff;
    }
    if ((pbVar7[1] & 0x10) == 0) {
      bVar2 = *pbVar7;
      if ((((bVar2 == 0x80) || (bVar2 == 1)) || (bVar2 == 10)) ||
         (((byte)(bVar2 + 0x60) < 2 || (bVar2 == 0x83)))) {
        uVar3 = (uint)bVar2;
        if ((uVar3 < 0xa2) && (0x9f < uVar3)) {
          if (param_1 == 0) {
            iVar1 = 0;
          }
          else {
            sVar4 = *(short *)(param_1 + uVar3 * 0xc + -0x5bc);
            *(undefined *)(param_1 + uVar3 + 0x134) = 1;
            iVar1 = (int)sVar4 << 1;
          }
        }
        else {
          uVar3 = FUN_80281b24(bVar2,param_3,param_4);
          iVar1 = (uVar3 & 0xffff) - 0x2000;
        }
        goto LAB_80282168;
      }
      if (bVar2 == 0xa3) {
        if (param_1 == 0) {
          uVar3 = 0;
        }
        else {
          uVar3 = *(uint *)(param_1 + 0x158) >> 9;
        }
      }
      else if (bVar2 < 0xa3) {
        if (bVar2 < 0xa2) {
LAB_8028236c:
          uVar3 = FUN_80281b24(bVar2,param_3,param_4);
          uVar3 = uVar3 & 0xffff;
        }
        else if (param_1 == 0) {
          uVar3 = 0;
        }
        else {
          uVar3 = (uint)*(byte *)(param_1 + 0x12f) << 7;
        }
      }
      else {
        if (0xa4 < bVar2) goto LAB_8028236c;
        if (param_1 == 0) {
          uVar3 = 0;
        }
        else {
          FUN_8028646c(DAT_803de278 -
                       ((uint)(DAT_803de27c < *(uint *)(param_1 + 0x94)) + *(int *)(param_1 + 0x90))
                       ,DAT_803de27c - *(uint *)(param_1 + 0x94),8);
          uVar3 = extraout_r4;
          if (0x3fff < (int)extraout_r4) {
            uVar3 = 0x3fff;
          }
          *(undefined *)(param_1 + 0xa8) = 1;
        }
      }
      uVar3 = (int)(uVar3 * (*(int *)(pbVar7 + 4) >> 1)) >> 0xf;
      if (0x3fff < (int)uVar3) {
        uVar3 = 0x3fff;
      }
      bVar2 = pbVar7[1] & 0xf;
      if (bVar2 == 2) {
        if (unaff_r29 == 0) {
          uVar5 = uVar5 * uVar3 >> 0xe;
          if (0x3fff < uVar5) {
            uVar5 = 0x3fff;
          }
        }
        else {
          iVar1 = (int)(uVar3 * (uVar5 - 0x2000)) >> 0xe;
          if (iVar1 < -0x2000) {
            iVar1 = -0x2000;
          }
          else if (0x1fff < iVar1) {
            iVar1 = 0x1fff;
          }
          uVar5 = iVar1 + 0x2000;
        }
      }
      else if (bVar2 < 2) {
        if ((pbVar7[1] & 0xf) == 0) {
          unaff_r29 = 0;
          uVar5 = uVar3;
        }
        else if (unaff_r29 == 0) {
          uVar5 = uVar5 + uVar3;
          if (0x3fff < uVar5) {
            uVar5 = 0x3fff;
          }
        }
        else {
          iVar1 = uVar5 + uVar3 + -0x2000;
          if (iVar1 < -0x2000) {
            iVar1 = -0x2000;
          }
          else if (0x1fff < iVar1) {
            iVar1 = 0x1fff;
          }
          uVar5 = iVar1 + 0x2000;
        }
      }
      else if (bVar2 < 4) {
        if (unaff_r29 == 0) {
          uVar5 = uVar5 - uVar3;
          if ((int)uVar5 < 0x4000) {
            if ((int)uVar5 < 0) {
              uVar5 = 0;
            }
          }
          else {
            uVar5 = 0x3fff;
          }
        }
        else {
          iVar1 = (uVar5 - 0x2000) - uVar3;
          if (iVar1 < -0x2000) {
            iVar1 = -0x2000;
          }
          else if (0x1fff < iVar1) {
            iVar1 = 0x1fff;
          }
          uVar5 = iVar1 + 0x2000;
        }
      }
    }
    else {
      if (param_1 == 0) {
        iVar1 = 0;
      }
      else {
        sVar4 = FUN_80276a08(param_1,0,*pbVar7);
        iVar1 = (int)sVar4;
      }
LAB_80282168:
      iVar1 = iVar1 * (*(int *)(pbVar7 + 4) >> 1) >> 0xf;
      if (iVar1 < -0x2000) {
        iVar1 = -0x2000;
      }
      else if (0x1fff < iVar1) {
        iVar1 = 0x1fff;
      }
      bVar2 = pbVar7[1] & 0xf;
      if (bVar2 == 2) {
        if (unaff_r29 == 0) {
          uVar5 = iVar1 * uVar5 >> 0xd;
          unaff_r29 = 1;
        }
        else {
          uVar5 = (int)((uVar5 - 0x2000) * iVar1) >> 0xd;
        }
        if ((int)uVar5 < -0x2000) {
          uVar5 = 0xffffe000;
        }
        else if (0x1fff < (int)uVar5) {
          uVar5 = 0x1fff;
        }
        uVar5 = uVar5 + 0x2000;
      }
      else if (bVar2 < 2) {
        if ((pbVar7[1] & 0xf) == 0) {
          unaff_r29 = 1;
          uVar5 = iVar1 + 0x2000;
        }
        else if (unaff_r29 == 0) {
          uVar5 = uVar5 + iVar1;
          if ((int)uVar5 < 0x4000) {
            if ((int)uVar5 < 0) {
              uVar5 = 0;
            }
          }
          else {
            uVar5 = 0x3fff;
          }
        }
        else {
          iVar1 = uVar5 + iVar1 + -0x2000;
          if (iVar1 < -0x2000) {
            iVar1 = -0x2000;
          }
          else if (0x1fff < iVar1) {
            iVar1 = 0x1fff;
          }
          uVar5 = iVar1 + 0x2000;
        }
      }
      else if (bVar2 < 4) {
        if (unaff_r29 == 0) {
          uVar5 = uVar5 - iVar1;
          if ((int)uVar5 < 0x4000) {
            if ((int)uVar5 < 0) {
              uVar5 = 0;
            }
          }
          else {
            uVar5 = 0x3fff;
          }
        }
        else {
          iVar1 = (uVar5 - 0x2000) - iVar1;
          if (iVar1 < -0x2000) {
            iVar1 = -0x2000;
          }
          else if (0x1fff < iVar1) {
            iVar1 = 0x1fff;
          }
          uVar5 = iVar1 + 0x2000;
        }
      }
    }
    pbVar7 = pbVar7 + 8;
    uVar6 = uVar6 + 1;
  } while( true );
}

