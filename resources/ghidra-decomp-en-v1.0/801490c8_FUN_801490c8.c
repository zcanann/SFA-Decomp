// Function: FUN_801490c8
// Entry: 801490c8
// Size: 2796 bytes

/* WARNING: Removing unreachable block (ram,0x80149b94) */

void FUN_801490c8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  short sVar1;
  byte bVar2;
  float fVar3;
  short *psVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined8 uVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  undefined2 local_98 [2];
  int local_94;
  uint local_90;
  undefined4 local_8c;
  float local_88;
  float local_84;
  float local_80;
  int local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860d8();
  psVar4 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  uVar5 = FUN_8002b9ec();
  local_78 = DAT_802c2200;
  local_74 = DAT_802c2204;
  local_70 = DAT_802c2208;
  local_6c = DAT_802c220c;
  uVar9 = 2;
  if ((*(uint *)(iVar8 + 0x2dc) & 0x1800) != 0) goto LAB_80149b94;
  if ((*(uint *)(iVar8 + 0x2e4) & 1) == 0) {
    FUN_80035f00(psVar4);
  }
  else {
    FUN_80035f20(psVar4);
  }
  iVar6 = FUN_80036770(psVar4,&local_7c,&local_8c,&local_90,&local_5c,&local_58,&local_54);
  local_5c = local_5c + FLOAT_803dcdd8;
  local_54 = local_54 + FLOAT_803dcddc;
  *(float *)(iVar8 + 0x2d4) = *(float *)(iVar8 + 0x2d4) - FLOAT_803db414;
  if (iVar6 == 0x1a) {
    if (*(float *)(iVar8 + 0x2d4) < FLOAT_803e2574) {
      *(float *)(iVar8 + 0x2d4) = FLOAT_803e2588;
    }
    else {
      iVar6 = 0;
    }
  }
  *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & 0xffffffcf;
  *(float *)(iVar8 + 0x2d8) = *(float *)(iVar8 + 0x2d8) - FLOAT_803db414;
  if (*(float *)(iVar8 + 0x2d8) < FLOAT_803e2574) {
    *(float *)(iVar8 + 0x2d8) = FLOAT_803e2574;
  }
  FUN_802972b4(uVar5,&local_94,&local_80,&local_84,&local_88,local_98);
  FUN_80149bb4((double)local_80,iVar8,local_94,local_98[0]);
  if (iVar6 == 0) {
    if ((*(uint *)(iVar8 + 0x2dc) & 0x40000000) != 0) {
      *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & 0xffffbfff;
    }
  }
  else if ((param_3 & 0xff) == 0) {
    if ((local_94 != 0) &&
       (((*(short *)(local_7c + 0x44) == 1 || (*(short *)(local_7c + 0x44) == 0x2d)) &&
        ((*(uint *)(iVar8 + 0x2e4) & 0x200) != 0)))) {
      if ((FLOAT_803e2590 <= local_88) && (local_88 <= FLOAT_803e256c)) {
        *(float *)(iVar8 + 0x304) = local_88;
      }
      fVar3 = FLOAT_803e2574;
      *(float *)(psVar4 + 0x12) = FLOAT_803e2574;
      *(float *)(psVar4 + 0x14) = fVar3;
      if ((*(uint *)(iVar8 + 0x2dc) & 0x40) == 0) {
        *(float *)(psVar4 + 0x16) = local_84;
      }
      else {
        *(float *)(psVar4 + 0x16) = FLOAT_803e2594 * local_84;
      }
      FUN_80021ac8(psVar4,psVar4 + 0x12);
    }
    uStack52 = local_90 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar8 + 0x2d8) =
         FLOAT_803e2598 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2580) +
         *(float *)(iVar8 + 0x2d8);
    if ((*(uint *)(iVar8 + 0x2dc) & 0x4000) != 0) {
      *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x10;
    }
    if ((*(uint *)(iVar8 + 0x2dc) & 0x40) == 0) {
      *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x4000;
    }
    *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) | 0x20;
    local_68 = *(float *)(psVar4 + 0xc) - local_5c;
    local_64 = *(float *)(psVar4 + 0xe) - local_58;
    local_60 = *(float *)(psVar4 + 0x10) - local_54;
    uVar7 = FUN_800217c0(-(double)local_68,-(double)local_60);
    uVar7 = (uVar7 & 0xffff) - ((int)*psVar4 & 0xffffU);
    if (0x8000 < (int)uVar7) {
      uVar7 = uVar7 - 0xffff;
    }
    if ((int)uVar7 < -0x8000) {
      uVar7 = uVar7 + 0xffff;
    }
    uVar7 = (uVar7 & 0xffff) >> 0xd;
    uVar12 = FUN_802931a0((double)(local_68 * local_68 + local_60 * local_60));
    uVar11 = FUN_802931a0((double)(local_64 * local_64));
    sVar1 = psVar4[0x23];
    if (sVar1 == 0x4d7) {
      FUN_801561ec(uVar11,uVar11,psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
    }
    else if (sVar1 < 0x4d7) {
      if (sVar1 == 0x281) {
LAB_80149630:
        FUN_80152004(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
      else if (sVar1 < 0x281) {
        if (sVar1 != 0x13a) {
          if (0x139 < sVar1) {
            if (sVar1 == 0x25d) {
              FUN_80155770(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
            }
            else {
              if ((0x25c < sVar1) || (sVar1 != 0x251)) goto LAB_801498d8;
              FUN_801544e8(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
            }
            goto LAB_8014991c;
          }
          if (sVar1 == 0xd8) goto LAB_80149630;
          if ((0xd7 < sVar1) || (sVar1 != 0x11)) goto LAB_801498d8;
        }
LAB_80149600:
        uVar9 = FUN_801504f8(uVar12,psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
      else if (sVar1 == 0x427) {
        FUN_8014fef8(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
      else if (sVar1 < 0x427) {
        if (sVar1 == 0x3fe) {
LAB_801496a8:
          FUN_80152fa8(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
        else {
          if ((0x3fd < sVar1) || (sVar1 != 0x369)) goto LAB_801498d8;
          FUN_80153cf8(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
      }
      else if (sVar1 == 0x458) {
        FUN_80156a44(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
      else if (sVar1 < 0x458) {
        if (sVar1 < 0x457) goto LAB_801498d8;
        FUN_80155e10(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
      else {
        if (sVar1 != 0x4ac) goto LAB_801498d8;
        FUN_80156d44(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
    }
    else {
      if (sVar1 == 0x7a6) goto LAB_80149600;
      if (sVar1 < 0x7a6) {
        if (sVar1 == 0x613) {
          FUN_80152440(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
        else if (sVar1 < 0x613) {
          if (sVar1 < 0x5ba) {
            if (sVar1 == 0x58b) {
              FUN_80153790(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
              goto LAB_8014991c;
            }
            if ((0x58a < sVar1) && (0x5b6 < sVar1)) goto LAB_80149600;
          }
          else if (sVar1 == 0x5e1) goto LAB_80149600;
LAB_801498d8:
          FUN_8014fef8(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
        else if (sVar1 < 0x6a2) {
          if (sVar1 != 0x642) goto LAB_801498d8;
          FUN_80152b2c(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
        else {
          if (0x6a5 < sVar1) goto LAB_801498d8;
          FUN_80157ebc(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
        }
      }
      else {
        if (sVar1 != 0x842) {
          if (sVar1 < 0x842) {
            if (sVar1 != 0x7c7) {
              if (sVar1 < 0x7c7) {
                if (0x7c5 < sVar1) goto LAB_801496a8;
              }
              else if (sVar1 < 0x7c9) {
                FUN_801598dc(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
                goto LAB_8014991c;
              }
            }
          }
          else {
            if (sVar1 == 0x851) {
              FUN_8015ad5c(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
              goto LAB_8014991c;
            }
            if ((sVar1 < 0x851) && (sVar1 == 0x84b)) goto LAB_80149810;
          }
          goto LAB_801498d8;
        }
LAB_80149810:
        FUN_8015a660(psVar4,iVar8,local_7c,iVar6,local_8c,local_90,&local_5c,uVar7);
      }
    }
  }
  else if (iVar6 == 0x10) {
    *(uint *)(iVar8 + 0x2e8) = *(uint *)(iVar8 + 0x2e8) | 0x10;
  }
  else {
    local_48 = FLOAT_803e258c;
    (**(code **)(*DAT_803dcab4 + 0xc))(psVar4,0x7fb,0,100,&local_50);
    (**(code **)(*DAT_803dcab4 + 0xc))(psVar4,0x7fc,0,0x32,0);
    FUN_8002af98(psVar4);
    *(undefined2 *)(iVar8 + 0x2b0) = 0;
    *(uint *)(iVar8 + 0x2e8) = *(uint *)(iVar8 + 0x2e8) & 0xffffffdf;
    *(uint *)(iVar8 + 0x2e8) = *(uint *)(iVar8 + 0x2e8) | 0x200;
    FUN_8000bb18(psVar4,0x47b);
  }
LAB_8014991c:
  if ((*(uint *)(iVar8 + 0x2e8) & 0x208) != 0) {
    local_44 = local_5c;
    local_40 = local_58;
    local_3c = local_54;
    if (*(int *)(iVar8 + 0x368) == 0) {
      uVar5 = FUN_8001f4c8(0,1);
      *(undefined4 *)(iVar8 + 0x368) = uVar5;
    }
    if ((*(uint *)(iVar8 + 0x2e8) & 0x200) == 0) {
      if ((*(byte *)(iVar8 + 0x2f1) & 0x10) == 0) {
        if ((*(byte *)(iVar8 + 0x2f1) & 8) == 0) {
          FUN_8009a1dc((double)FLOAT_803e259c,psVar4,&local_50,1,*(undefined4 *)(iVar8 + 0x368));
        }
        else {
          FUN_8009a1dc((double)FLOAT_803e259c,psVar4,&local_50,2,*(undefined4 *)(iVar8 + 0x368));
        }
      }
      else {
        FUN_8009a1dc((double)FLOAT_803e259c,psVar4,&local_50,3,*(undefined4 *)(iVar8 + 0x368));
      }
    }
    else {
      FUN_8009a1dc((double)FLOAT_803e259c,psVar4,&local_50,1,*(undefined4 *)(iVar8 + 0x368));
    }
    FUN_8002ac30(psVar4,0xf,200,0,0,1);
  }
  *(float *)(iVar8 + 0x2d0) = *(float *)(iVar8 + 0x2d0) - FLOAT_803db414;
  if (*(float *)(iVar8 + 0x2d0) < FLOAT_803e2574) {
    *(float *)(iVar8 + 0x2d0) = FLOAT_803e2574;
  }
  if ((*(uint *)(iVar8 + 0x2e8) & 0x10) == 0) {
    if ((*(uint *)(iVar8 + 0x2e8) & 0x20) == 0) {
      bVar2 = *(byte *)(iVar8 + 0x2f6) >> 3;
      if (bVar2 != 0) {
        *(byte *)(iVar8 + 0x2f6) = (bVar2 - 1) * '\b' | *(byte *)(iVar8 + 0x2f6) & 7;
      }
    }
    else {
      if (*(byte *)(iVar8 + 0x2f6) >> 3 == 0) {
        FUN_8000bb18(psVar4,0x47a);
        *(byte *)(iVar8 + 0x2f6) = *(byte *)(iVar8 + 0x2f6) & 7 | 0xf8;
      }
      FUN_8002b050(psVar4,300);
    }
  }
  else {
    if (*(float *)(iVar8 + 0x2d0) <= FLOAT_803e2574) {
      local_44 = local_5c;
      local_40 = local_58;
      local_3c = local_54;
      local_48 = FLOAT_803e256c;
      local_4c = 0;
      local_4e = 0;
      local_50 = 0;
      if (DAT_803dda50 != (int *)0x0) {
        (**(code **)(*DAT_803dda50 + 4))(0,1,&local_50,0x401,0xffffffff,&local_78);
      }
      *(float *)(iVar8 + 0x2d0) = FLOAT_803e25a0;
      if (*(int *)(iVar8 + 0x368) == 0) {
        uVar5 = FUN_8001f4c8(0,1);
        *(undefined4 *)(iVar8 + 0x368) = uVar5;
      }
      FUN_8009a1dc((double)FLOAT_803e259c,psVar4,&local_50,4,*(undefined4 *)(iVar8 + 0x368));
    }
    iVar6 = *(int *)(iVar8 + 0x29c);
    if ((iVar6 != 0) && (*(short *)(iVar6 + 0x44) == 1)) {
      FUN_802961fc(iVar6,uVar9);
    }
  }
  *(uint *)(iVar8 + 0x2e8) = *(uint *)(iVar8 + 0x2e8) & 0xfffffdc7;
LAB_80149b94:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286124();
  return;
}

