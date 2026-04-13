// Function: FUN_80149528
// Entry: 80149528
// Size: 2796 bytes

/* WARNING: Removing unreachable block (ram,0x80149ff4) */
/* WARNING: Removing unreachable block (ram,0x80149538) */

void FUN_80149528(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11)

{
  ushort uVar1;
  float fVar2;
  ushort *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  byte bVar8;
  int *piVar7;
  int iVar9;
  double dVar10;
  double dVar11;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar12;
  undefined2 local_98 [2];
  uint local_94;
  uint local_90;
  int local_8c;
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
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar12 >> 0x20);
  iVar9 = (int)uVar12;
  iVar4 = FUN_8002bac4();
  local_78 = DAT_802c2980;
  local_74 = DAT_802c2984;
  local_70 = DAT_802c2988;
  local_6c = DAT_802c298c;
  bVar8 = 2;
  if ((*(uint *)(iVar9 + 0x2dc) & 0x1800) != 0) goto LAB_80149ff4;
  if ((*(uint *)(iVar9 + 0x2e4) & 1) == 0) {
    FUN_80035ff8((int)puVar3);
  }
  else {
    FUN_80036018((int)puVar3);
  }
  iVar5 = FUN_80036868((int)puVar3,&local_7c,&local_8c,&local_90,&local_5c,&local_58,&local_54);
  local_5c = local_5c + FLOAT_803dda58;
  local_54 = local_54 + FLOAT_803dda5c;
  *(float *)(iVar9 + 0x2d4) = *(float *)(iVar9 + 0x2d4) - FLOAT_803dc074;
  if (iVar5 == 0x1a) {
    if (*(float *)(iVar9 + 0x2d4) < FLOAT_803e31fc) {
      *(float *)(iVar9 + 0x2d4) = FLOAT_803e3220;
    }
    else {
      iVar5 = 0;
    }
  }
  *(uint *)(iVar9 + 0x2dc) = *(uint *)(iVar9 + 0x2dc) & 0xffffffcf;
  *(float *)(iVar9 + 0x2d8) = *(float *)(iVar9 + 0x2d8) - FLOAT_803dc074;
  if (*(float *)(iVar9 + 0x2d8) < FLOAT_803e31fc) {
    *(float *)(iVar9 + 0x2d8) = FLOAT_803e31fc;
  }
  FUN_80297a14(iVar4,&local_94,&local_80,&local_84,&local_88,local_98);
  FUN_8014a014((double)local_80,iVar9,local_94,local_98[0]);
  if (iVar5 == 0) {
    if ((*(uint *)(iVar9 + 0x2dc) & 0x40000000) != 0) {
      *(uint *)(iVar9 + 0x2dc) = *(uint *)(iVar9 + 0x2dc) & 0xffffbfff;
    }
  }
  else if ((param_11 & 0xff) == 0) {
    if ((local_94 != 0) &&
       (((*(short *)(local_7c + 0x44) == 1 || (*(short *)(local_7c + 0x44) == 0x2d)) &&
        ((*(uint *)(iVar9 + 0x2e4) & 0x200) != 0)))) {
      if ((FLOAT_803e3208 <= local_88) && (local_88 <= FLOAT_803e3200)) {
        *(float *)(iVar9 + 0x304) = local_88;
      }
      fVar2 = FLOAT_803e31fc;
      *(float *)(puVar3 + 0x12) = FLOAT_803e31fc;
      *(float *)(puVar3 + 0x14) = fVar2;
      if ((*(uint *)(iVar9 + 0x2dc) & 0x40) == 0) {
        *(float *)(puVar3 + 0x16) = local_84;
      }
      else {
        *(float *)(puVar3 + 0x16) = FLOAT_803e3228 * local_84;
      }
      FUN_80021b8c(puVar3,(float *)(puVar3 + 0x12));
    }
    uStack_34 = local_90 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar9 + 0x2d8) =
         FLOAT_803e322c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3218) +
         *(float *)(iVar9 + 0x2d8);
    if ((*(uint *)(iVar9 + 0x2dc) & 0x4000) != 0) {
      *(uint *)(iVar9 + 0x2dc) = *(uint *)(iVar9 + 0x2dc) | 0x10;
    }
    if ((*(uint *)(iVar9 + 0x2dc) & 0x40) == 0) {
      *(uint *)(iVar9 + 0x2dc) = *(uint *)(iVar9 + 0x2dc) | 0x4000;
    }
    *(uint *)(iVar9 + 0x2dc) = *(uint *)(iVar9 + 0x2dc) | 0x20;
    local_68 = *(float *)(puVar3 + 0xc) - local_5c;
    local_64 = *(float *)(puVar3 + 0xe) - local_58;
    local_60 = *(float *)(puVar3 + 0x10) - local_54;
    uVar6 = FUN_80021884();
    uVar6 = (uVar6 & 0xffff) - (uint)*puVar3;
    if (0x8000 < (int)uVar6) {
      uVar6 = uVar6 - 0xffff;
    }
    if ((int)uVar6 < -0x8000) {
      uVar6 = uVar6 + 0xffff;
    }
    uVar6 = (uVar6 & 0xffff) >> 0xd;
    dVar10 = FUN_80293900((double)(local_68 * local_68 + local_60 * local_60));
    dVar11 = FUN_80293900((double)(local_64 * local_64));
    uVar1 = puVar3[0x23];
    if (uVar1 == 0x4d7) {
      FUN_80156698((uint)puVar3,iVar9,local_7c,iVar5);
    }
    else if ((short)uVar1 < 0x4d7) {
      if (uVar1 == 0x281) {
LAB_80149a90:
        FUN_80152498((uint)puVar3,iVar9);
      }
      else if ((short)uVar1 < 0x281) {
        if (uVar1 != 0x13a) {
          if (0x139 < (short)uVar1) {
            if (uVar1 == 0x25d) {
              FUN_80155c1c((uint)puVar3,iVar9,local_7c,iVar5);
            }
            else {
              if ((0x25c < (short)uVar1) || (uVar1 != 0x251)) goto LAB_80149d38;
              FUN_80154994((uint)puVar3,iVar9,local_7c,iVar5);
            }
            goto LAB_80149d7c;
          }
          if (uVar1 == 0xd8) goto LAB_80149a90;
          if ((0xd7 < (short)uVar1) || (uVar1 != 0x11)) goto LAB_80149d38;
        }
LAB_80149a60:
        bVar8 = FUN_8015098c(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                             iVar9,local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
      }
      else if (uVar1 == 0x427) {
        FUN_8015038c(puVar3,iVar9,local_7c,iVar5);
      }
      else if ((short)uVar1 < 0x427) {
        if (uVar1 == 0x3fe) {
LAB_80149b08:
          FUN_80153454((uint)puVar3,iVar9,local_7c,iVar5);
        }
        else {
          if ((0x3fd < (short)uVar1) || (uVar1 != 0x369)) goto LAB_80149d38;
          FUN_801541a4(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar3,
                       iVar9,local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
        }
      }
      else if (uVar1 == 0x458) {
        FUN_80156ef0(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar3,
                     iVar9,local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
      }
      else if ((short)uVar1 < 0x458) {
        if ((short)uVar1 < 0x457) goto LAB_80149d38;
        FUN_801562bc(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar3,
                     iVar9,local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
      }
      else {
        if (uVar1 != 0x4ac) goto LAB_80149d38;
        FUN_801571f0((uint)puVar3,iVar9,local_7c,iVar5);
      }
    }
    else {
      if (uVar1 == 0x7a6) goto LAB_80149a60;
      if ((short)uVar1 < 0x7a6) {
        if (uVar1 == 0x613) {
          FUN_801528ec(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar3,
                       iVar9,local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
        }
        else if ((short)uVar1 < 0x613) {
          if ((short)uVar1 < 0x5ba) {
            if (uVar1 == 0x58b) {
              FUN_80153c3c((uint)puVar3,iVar9,local_7c,iVar5,local_8c,local_90);
              goto LAB_80149d7c;
            }
            if ((0x58a < (short)uVar1) && (0x5b6 < (short)uVar1)) goto LAB_80149a60;
          }
          else if (uVar1 == 0x5e1) goto LAB_80149a60;
LAB_80149d38:
          FUN_8015038c(puVar3,iVar9,local_7c,iVar5);
        }
        else if ((short)uVar1 < 0x6a2) {
          if (uVar1 != 0x642) goto LAB_80149d38;
          FUN_80152fd8((uint)puVar3,iVar9,local_7c,iVar5);
        }
        else {
          if (0x6a5 < (short)uVar1) goto LAB_80149d38;
          FUN_80158368(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,iVar9,
                       local_7c,iVar5,local_8c,local_90,&local_5c,uVar6);
        }
      }
      else {
        if (uVar1 != 0x842) {
          if ((short)uVar1 < 0x842) {
            if (uVar1 != 0x7c7) {
              if ((short)uVar1 < 0x7c7) {
                if (0x7c5 < (short)uVar1) goto LAB_80149b08;
              }
              else if ((short)uVar1 < 0x7c9) {
                FUN_80159d88((uint)puVar3,iVar9,local_7c,iVar5);
                goto LAB_80149d7c;
              }
            }
          }
          else {
            if (uVar1 == 0x851) {
              FUN_8015b208();
              goto LAB_80149d7c;
            }
            if (((short)uVar1 < 0x851) && (uVar1 == 0x84b)) goto LAB_80149c70;
          }
          goto LAB_80149d38;
        }
LAB_80149c70:
        FUN_8015ab0c(dVar11,dVar11,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
  }
  else if (iVar5 == 0x10) {
    *(uint *)(iVar9 + 0x2e8) = *(uint *)(iVar9 + 0x2e8) | 0x10;
  }
  else {
    local_48 = FLOAT_803e3224;
    (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x7fb,0,100,&local_50);
    (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x7fc,0,0x32,0);
    FUN_8002b070((int)puVar3);
    *(undefined2 *)(iVar9 + 0x2b0) = 0;
    *(uint *)(iVar9 + 0x2e8) = *(uint *)(iVar9 + 0x2e8) & 0xffffffdf;
    *(uint *)(iVar9 + 0x2e8) = *(uint *)(iVar9 + 0x2e8) | 0x200;
    FUN_8000bb38((uint)puVar3,0x47b);
  }
LAB_80149d7c:
  if ((*(uint *)(iVar9 + 0x2e8) & 0x208) != 0) {
    local_44 = local_5c;
    local_40 = local_58;
    local_3c = local_54;
    if (*(int *)(iVar9 + 0x368) == 0) {
      piVar7 = FUN_8001f58c(0,'\x01');
      *(int **)(iVar9 + 0x368) = piVar7;
    }
    if ((*(uint *)(iVar9 + 0x2e8) & 0x200) == 0) {
      if ((*(byte *)(iVar9 + 0x2f1) & 0x10) == 0) {
        if ((*(byte *)(iVar9 + 0x2f1) & 8) == 0) {
          FUN_8009a468(puVar3,&local_50,1,*(int **)(iVar9 + 0x368));
        }
        else {
          FUN_8009a468(puVar3,&local_50,2,*(int **)(iVar9 + 0x368));
        }
      }
      else {
        FUN_8009a468(puVar3,&local_50,3,*(int **)(iVar9 + 0x368));
      }
    }
    else {
      FUN_8009a468(puVar3,&local_50,1,*(int **)(iVar9 + 0x368));
    }
    FUN_8002ad08(puVar3,0xf,200,0,0,1);
  }
  *(float *)(iVar9 + 0x2d0) = *(float *)(iVar9 + 0x2d0) - FLOAT_803dc074;
  if (*(float *)(iVar9 + 0x2d0) < FLOAT_803e31fc) {
    *(float *)(iVar9 + 0x2d0) = FLOAT_803e31fc;
  }
  if ((*(uint *)(iVar9 + 0x2e8) & 0x10) == 0) {
    if ((*(uint *)(iVar9 + 0x2e8) & 0x20) == 0) {
      bVar8 = *(byte *)(iVar9 + 0x2f6) >> 3;
      if (bVar8 != 0) {
        *(byte *)(iVar9 + 0x2f6) = (bVar8 - 1) * '\b' | *(byte *)(iVar9 + 0x2f6) & 7;
      }
    }
    else {
      if (*(byte *)(iVar9 + 0x2f6) >> 3 == 0) {
        FUN_8000bb38((uint)puVar3,0x47a);
        *(byte *)(iVar9 + 0x2f6) = *(byte *)(iVar9 + 0x2f6) & 7 | 0xf8;
      }
      FUN_8002b128(puVar3,300);
    }
  }
  else {
    if (*(float *)(iVar9 + 0x2d0) <= FLOAT_803e31fc) {
      local_44 = local_5c;
      local_40 = local_58;
      local_3c = local_54;
      local_48 = FLOAT_803e3200;
      local_4c = 0;
      local_4e = 0;
      local_50 = 0;
      if (DAT_803de6d0 != (int *)0x0) {
        (**(code **)(*DAT_803de6d0 + 4))(0,1,&local_50,0x401,0xffffffff,&local_78);
      }
      *(float *)(iVar9 + 0x2d0) = FLOAT_803e3234;
      if (*(int *)(iVar9 + 0x368) == 0) {
        piVar7 = FUN_8001f58c(0,'\x01');
        *(int **)(iVar9 + 0x368) = piVar7;
      }
      FUN_8009a468(puVar3,&local_50,4,*(int **)(iVar9 + 0x368));
    }
    iVar4 = *(int *)(iVar9 + 0x29c);
    if ((iVar4 != 0) && (*(short *)(iVar4 + 0x44) == 1)) {
      FUN_8029695c(iVar4,bVar8);
    }
  }
  *(uint *)(iVar9 + 0x2e8) = *(uint *)(iVar9 + 0x2e8) & 0xfffffdc7;
LAB_80149ff4:
  FUN_80286888();
  return;
}

