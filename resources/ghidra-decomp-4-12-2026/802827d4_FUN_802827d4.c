// Function: FUN_802827d4
// Entry: 802827d4
// Size: 1160 bytes

/* WARNING: Removing unreachable block (ram,0x80282b1c) */
/* WARNING: Removing unreachable block (ram,0x80282918) */

uint FUN_802827d4(int param_1,byte *param_2,uint param_3,uint param_4)

{
  short sVar1;
  uint uVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int unaff_r29;
  byte *pbVar8;
  undefined8 uVar9;
  
  uVar6 = 0;
  uVar7 = 0;
  pbVar8 = param_2;
  do {
    if (param_2[0x22] <= uVar7) {
      *(short *)(param_2 + 0x20) = (short)uVar6;
      return uVar6 & 0xffff;
    }
    if ((pbVar8[1] & 0x10) == 0) {
      uVar5 = (uint)*pbVar8;
      if ((((uVar5 == 0x80) || (uVar5 == 1)) || (uVar5 == 10)) ||
         (((uVar5 - 0xa0 & 0xff) < 2 || (uVar5 == 0x83)))) {
        uVar2 = (uint)*pbVar8;
        if ((uVar2 < 0xa2) && (0x9f < uVar2)) {
          if (param_1 == 0) {
            iVar4 = 0;
          }
          else {
            sVar1 = *(short *)(param_1 + uVar2 * 0xc + -0x5bc);
            *(undefined *)(param_1 + uVar2 + 0x134) = 1;
            iVar4 = (int)sVar1 << 1;
          }
        }
        else {
          uVar5 = FUN_80282288(uVar5,param_3,param_4);
          iVar4 = (uVar5 & 0xffff) - 0x2000;
        }
        goto LAB_802828cc;
      }
      if (uVar5 == 0xa3) {
        if (param_1 == 0) {
          uVar5 = 0;
        }
        else {
          uVar5 = *(uint *)(param_1 + 0x158) >> 9;
        }
      }
      else if (uVar5 < 0xa3) {
        if (uVar5 < 0xa2) {
LAB_80282ad0:
          uVar5 = FUN_80282288(uVar5,param_3,param_4);
          uVar5 = uVar5 & 0xffff;
        }
        else if (param_1 == 0) {
          uVar5 = 0;
        }
        else {
          uVar5 = (uint)*(byte *)(param_1 + 0x12f) << 7;
        }
      }
      else {
        if (0xa4 < uVar5) goto LAB_80282ad0;
        if (param_1 == 0) {
          uVar5 = 0;
        }
        else {
          uVar9 = FUN_80286bd0(DAT_803deef8 -
                               ((uint)(DAT_803deefc < *(uint *)(param_1 + 0x94)) +
                               *(int *)(param_1 + 0x90)),DAT_803deefc - *(uint *)(param_1 + 0x94),8)
          ;
          uVar5 = (uint)uVar9;
          if (0x3fff < (int)uVar5) {
            uVar5 = 0x3fff;
          }
          *(undefined *)(param_1 + 0xa8) = 1;
        }
      }
      uVar5 = (int)(uVar5 * (*(int *)(pbVar8 + 4) >> 1)) >> 0xf;
      if (0x3fff < (int)uVar5) {
        uVar5 = 0x3fff;
      }
      bVar3 = pbVar8[1] & 0xf;
      if (bVar3 == 2) {
        if (unaff_r29 == 0) {
          uVar6 = uVar6 * uVar5 >> 0xe;
          if (0x3fff < uVar6) {
            uVar6 = 0x3fff;
          }
        }
        else {
          iVar4 = (int)(uVar5 * (uVar6 - 0x2000)) >> 0xe;
          if (iVar4 < -0x2000) {
            iVar4 = -0x2000;
          }
          else if (0x1fff < iVar4) {
            iVar4 = 0x1fff;
          }
          uVar6 = iVar4 + 0x2000;
        }
      }
      else if (bVar3 < 2) {
        if ((pbVar8[1] & 0xf) == 0) {
          unaff_r29 = 0;
          uVar6 = uVar5;
        }
        else if (unaff_r29 == 0) {
          uVar6 = uVar6 + uVar5;
          if (0x3fff < uVar6) {
            uVar6 = 0x3fff;
          }
        }
        else {
          iVar4 = uVar6 + uVar5 + -0x2000;
          if (iVar4 < -0x2000) {
            iVar4 = -0x2000;
          }
          else if (0x1fff < iVar4) {
            iVar4 = 0x1fff;
          }
          uVar6 = iVar4 + 0x2000;
        }
      }
      else if (bVar3 < 4) {
        if (unaff_r29 == 0) {
          uVar6 = uVar6 - uVar5;
          if ((int)uVar6 < 0x4000) {
            if ((int)uVar6 < 0) {
              uVar6 = 0;
            }
          }
          else {
            uVar6 = 0x3fff;
          }
        }
        else {
          iVar4 = (uVar6 - 0x2000) - uVar5;
          if (iVar4 < -0x2000) {
            iVar4 = -0x2000;
          }
          else if (0x1fff < iVar4) {
            iVar4 = 0x1fff;
          }
          uVar6 = iVar4 + 0x2000;
        }
      }
    }
    else {
      if (param_1 == 0) {
        iVar4 = 0;
      }
      else {
        iVar4 = FUN_8027716c(param_1,0,(uint)*pbVar8);
        iVar4 = (int)(short)iVar4;
      }
LAB_802828cc:
      iVar4 = iVar4 * (*(int *)(pbVar8 + 4) >> 1) >> 0xf;
      if (iVar4 < -0x2000) {
        iVar4 = -0x2000;
      }
      else if (0x1fff < iVar4) {
        iVar4 = 0x1fff;
      }
      bVar3 = pbVar8[1] & 0xf;
      if (bVar3 == 2) {
        if (unaff_r29 == 0) {
          uVar6 = iVar4 * uVar6 >> 0xd;
          unaff_r29 = 1;
        }
        else {
          uVar6 = (int)((uVar6 - 0x2000) * iVar4) >> 0xd;
        }
        if ((int)uVar6 < -0x2000) {
          uVar6 = 0xffffe000;
        }
        else if (0x1fff < (int)uVar6) {
          uVar6 = 0x1fff;
        }
        uVar6 = uVar6 + 0x2000;
      }
      else if (bVar3 < 2) {
        if ((pbVar8[1] & 0xf) == 0) {
          unaff_r29 = 1;
          uVar6 = iVar4 + 0x2000;
        }
        else if (unaff_r29 == 0) {
          uVar6 = uVar6 + iVar4;
          if ((int)uVar6 < 0x4000) {
            if ((int)uVar6 < 0) {
              uVar6 = 0;
            }
          }
          else {
            uVar6 = 0x3fff;
          }
        }
        else {
          iVar4 = uVar6 + iVar4 + -0x2000;
          if (iVar4 < -0x2000) {
            iVar4 = -0x2000;
          }
          else if (0x1fff < iVar4) {
            iVar4 = 0x1fff;
          }
          uVar6 = iVar4 + 0x2000;
        }
      }
      else if (bVar3 < 4) {
        if (unaff_r29 == 0) {
          uVar6 = uVar6 - iVar4;
          if ((int)uVar6 < 0x4000) {
            if ((int)uVar6 < 0) {
              uVar6 = 0;
            }
          }
          else {
            uVar6 = 0x3fff;
          }
        }
        else {
          iVar4 = (uVar6 - 0x2000) - iVar4;
          if (iVar4 < -0x2000) {
            iVar4 = -0x2000;
          }
          else if (0x1fff < iVar4) {
            iVar4 = 0x1fff;
          }
          uVar6 = iVar4 + 0x2000;
        }
      }
    }
    pbVar8 = pbVar8 + 8;
    uVar7 = uVar7 + 1;
  } while( true );
}

