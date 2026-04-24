// Function: FUN_801d083c
// Entry: 801d083c
// Size: 2656 bytes

/* WARNING: Removing unreachable block (ram,0x801d1274) */

void FUN_801d083c(short *param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar5;
  undefined2 uVar6;
  int iVar4;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack104 [4];
  undefined auStack100 [12];
  float local_58;
  float local_54;
  undefined4 local_50;
  float local_4c [2];
  float local_44;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_8002b9ec();
  if ((*(byte *)(param_2 + 0x137) & 4) != 0) {
    *(undefined *)(param_2 + 0x136) = 6;
  }
  dVar10 = (double)(FLOAT_803db418 * (*(float *)(param_2 + 0x10c) - *(float *)(param_2 + 0x108)));
  switch(*(char *)(param_2 + 0x136)) {
  case '\0':
    if ((*(byte *)(param_2 + 0x137) & 0x10) == 0) {
      iVar4 = (**(code **)(*DAT_803dca58 + 0x24))(auStack104);
      if (iVar4 == 0) {
        uStack44 = (uint)*(byte *)(param_3 + 0x19);
        local_30 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0) <=
            *(float *)(param_2 + 0x108)) {
          uStack44 = (uint)*(byte *)(param_3 + 0x1f);
          local_30 = 0x43300000;
          if (*(float *)(param_2 + 0x108) <
              (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0)) {
            *(undefined *)(param_2 + 0x136) = 3;
          }
        }
        else {
          if ((*(byte *)(param_2 + 0x137) & 2) == 0) {
            uVar6 = FUN_801d129c((double)*(float *)(param_2 + 0x118),param_1,iVar3,param_2);
            *(undefined2 *)(param_2 + 0x130) = uVar6;
          }
          else {
            dVar10 = (double)(*(float *)(param_2 + 0x118) * *(float *)(param_2 + 0x118));
            while( true ) {
              dVar9 = (double)(*(float *)(param_2 + 0x68) - *(float *)(param_1 + 6));
              dVar8 = (double)(*(float *)(param_2 + 0x70) - *(float *)(param_1 + 10));
              if (dVar10 <= (double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8))) break;
              iVar3 = FUN_80010320((double)*(float *)(param_2 + 0x120),param_2);
              if ((iVar3 != 0) || (*(int *)(param_2 + 0x10) != 0)) {
                (**(code **)(*DAT_803dca9c + 0x90))(param_2);
              }
            }
            uVar6 = FUN_800217c0(-dVar9,-dVar8);
            *(undefined2 *)(param_2 + 0x130) = uVar6;
          }
          *(undefined *)(param_2 + 0x136) = 1;
          FUN_8000bb18(param_1,0xa0);
          *param_1 = *(short *)(param_2 + 0x130) + -0x4000;
        }
      }
      else {
        fVar1 = *(float *)(param_2 + 300) - FLOAT_803db414;
        *(float *)(param_2 + 300) = fVar1;
        if (fVar1 <= FLOAT_803e5288) {
          if ((param_1[0x58] & 0x800U) != 0) {
            local_58 = *(float *)(param_1 + 0xc);
            local_54 = FLOAT_803e528c + *(float *)(param_1 + 0xe);
            local_50 = *(undefined4 *)(param_1 + 0x10);
            (**(code **)(*DAT_803dca88 + 8))(param_1,0x7f0,auStack100,0x200001,0xffffffff,0);
          }
          *(float *)(param_2 + 300) = FLOAT_803e5290;
        }
      }
    }
    else {
      *(undefined *)(param_2 + 0x136) = 9;
    }
    break;
  case '\x01':
    if ((*(byte *)(param_2 + 0x137) & 0x10) == 0) {
      if ((*(byte *)(param_2 + 0x137) & 1) != 0) {
        *(undefined *)(param_2 + 0x136) = 0;
      }
    }
    else {
      *(undefined *)(param_2 + 0x136) = 9;
    }
    break;
  case '\x03':
  case '\a':
    if ((*(byte *)(param_2 + 0x137) & 0x10) != 0) {
      *(undefined *)(param_2 + 0x136) = 9;
      break;
    }
    if ((*(byte *)(param_2 + 0x137) & 1) != 0) {
      if (*(char *)(param_2 + 0x136) == '\x03') {
        *(undefined *)(param_2 + 0x136) = 4;
      }
      else {
        *(undefined *)(param_2 + 0x136) = 0;
      }
      break;
    }
  case '\x04':
    if ((*(byte *)(param_2 + 0x137) & 0x10) == 0) {
      sVar5 = FUN_800217c0(-(double)(*(float *)(param_1 + 6) - *(float *)(iVar3 + 0xc)),
                           -(double)(*(float *)(param_1 + 10) - *(float *)(iVar3 + 0x14)));
      *param_1 = sVar5;
      uStack44 = (uint)*(byte *)(param_3 + 0x1f);
      local_30 = 0x43300000;
      if (*(float *)(param_2 + 0x108) <=
          FLOAT_803e5294 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0)) {
        uStack44 = (uint)*(byte *)(param_3 + 0x19);
        local_30 = 0x43300000;
        if (*(float *)(param_2 + 0x108) <
            (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0)) {
          FUN_8000bb18(param_1,0xa0);
          if (dVar10 < (double)FLOAT_803e5298) {
            if ((*(byte *)(param_2 + 0x137) & 2) == 0) {
              uVar6 = FUN_801d129c((double)*(float *)(param_2 + 0x11c),param_1,iVar3,param_2);
              *(undefined2 *)(param_2 + 0x130) = uVar6;
            }
            else {
              dVar10 = (double)(*(float *)(param_2 + 0x11c) * *(float *)(param_2 + 0x11c));
              while( true ) {
                dVar9 = (double)(*(float *)(param_2 + 0x68) - *(float *)(param_1 + 6));
                dVar8 = (double)(*(float *)(param_2 + 0x70) - *(float *)(param_1 + 10));
                if (dVar10 <= (double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)))
                break;
                iVar3 = FUN_80010320((double)*(float *)(param_2 + 0x120),param_2);
                if ((iVar3 != 0) || (*(int *)(param_2 + 0x10) != 0)) {
                  (**(code **)(*DAT_803dca9c + 0x90))(param_2);
                }
              }
              uVar6 = FUN_800217c0(-dVar9,-dVar8);
              *(undefined2 *)(param_2 + 0x130) = uVar6;
            }
            *(undefined *)(param_2 + 0x136) = 5;
            *param_1 = *(short *)(param_2 + 0x130);
          }
          else {
            if ((*(byte *)(param_2 + 0x137) & 2) == 0) {
              uVar6 = FUN_801d129c((double)*(float *)(param_2 + 0x118),param_1,iVar3,param_2);
              *(undefined2 *)(param_2 + 0x130) = uVar6;
            }
            else {
              dVar10 = (double)(*(float *)(param_2 + 0x118) * *(float *)(param_2 + 0x118));
              while( true ) {
                dVar9 = (double)(*(float *)(param_2 + 0x68) - *(float *)(param_1 + 6));
                dVar8 = (double)(*(float *)(param_2 + 0x70) - *(float *)(param_1 + 10));
                if (dVar10 <= (double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)))
                break;
                iVar3 = FUN_80010320((double)*(float *)(param_2 + 0x120),param_2);
                if ((iVar3 != 0) || (*(int *)(param_2 + 0x10) != 0)) {
                  (**(code **)(*DAT_803dca9c + 0x90))(param_2);
                }
              }
              uVar6 = FUN_800217c0(-dVar9,-dVar8);
              *(undefined2 *)(param_2 + 0x130) = uVar6;
            }
            *(undefined *)(param_2 + 0x136) = 1;
            *param_1 = *(short *)(param_2 + 0x130) + -0x4000;
          }
        }
      }
      else {
        *(undefined *)(param_2 + 0x136) = 7;
      }
    }
    else {
      *(undefined *)(param_2 + 0x136) = 9;
    }
    break;
  case '\x05':
    if ((*(byte *)(param_2 + 0x137) & 0x11) == 0x11) {
      *(undefined *)(param_2 + 0x136) = 9;
    }
    uStack44 = (uint)*(byte *)(param_3 + 0x19);
    local_30 = 0x43300000;
    if ((*(float *)(param_2 + 0x108) <=
         FLOAT_803e5294 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c0)) ||
       ((*(byte *)(param_2 + 0x137) & 1) == 0)) {
      if ((double)FLOAT_803e5298 <= dVar10) {
        if ((*(byte *)(param_2 + 0x137) & 2) == 0) {
          uVar6 = FUN_801d129c((double)*(float *)(param_2 + 0x118),param_1,iVar3,param_2);
          *(undefined2 *)(param_2 + 0x130) = uVar6;
        }
        else {
          dVar10 = (double)(*(float *)(param_2 + 0x118) * *(float *)(param_2 + 0x118));
          while( true ) {
            dVar9 = (double)(*(float *)(param_2 + 0x68) - *(float *)(param_1 + 6));
            dVar8 = (double)(*(float *)(param_2 + 0x70) - *(float *)(param_1 + 10));
            if (dVar10 <= (double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8))) break;
            iVar3 = FUN_80010320((double)*(float *)(param_2 + 0x120),param_2);
            if ((iVar3 != 0) || (*(int *)(param_2 + 0x10) != 0)) {
              (**(code **)(*DAT_803dca9c + 0x90))(param_2);
            }
          }
          uVar6 = FUN_800217c0(-dVar9,-dVar8);
          *(undefined2 *)(param_2 + 0x130) = uVar6;
        }
        *(undefined *)(param_2 + 0x136) = 1;
        FUN_8000bb18(param_1,0xa0);
        *param_1 = *(short *)(param_2 + 0x130) + -0x4000;
      }
    }
    else {
      *(undefined *)(param_2 + 0x136) = 4;
    }
    break;
  case '\x06':
    if ((*(byte *)(param_2 + 0x137) & 0x10) != 0) {
      *(undefined *)(param_2 + 0x136) = 9;
    }
    break;
  case '\t':
    FUN_80035e30(param_1,1);
    FUN_8000da58(param_1,0x9b);
    if (*(float *)(param_2 + 0x124) <= FLOAT_803e5288) {
      uStack44 = FUN_800221a0(0xf0,300);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      *(float *)(param_2 + 0x124) = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e52c8)
      ;
    }
    fVar1 = *(float *)(param_2 + 0x124) - FLOAT_803db414;
    *(float *)(param_2 + 0x124) = fVar1;
    fVar2 = FLOAT_803e5288;
    if (FLOAT_803e5288 < fVar1) {
      fVar1 = *(float *)(param_2 + 0x128) - FLOAT_803db414;
      *(float *)(param_2 + 0x128) = fVar1;
      if (fVar1 <= fVar2) {
        local_58 = FLOAT_803e5294;
        local_54 = FLOAT_803e529c;
        if ((param_1[0x58] & 0x800U) != 0) {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x51d,auStack100,2,0xffffffff,0);
        }
        *(float *)(param_2 + 0x128) = FLOAT_803e52a0;
      }
      iVar4 = FUN_8001ffb4(0x12e);
      if (((iVar4 == 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) &&
         (dVar10 = (double)FUN_80021690(iVar3 + 0x18,param_1 + 0xc), dVar10 < (double)FLOAT_803e52a4
         )) {
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        if (param_1[0x23] == 0x658) {
          *(undefined2 *)(param_2 + 0x13c) = 0x18a;
          FUN_800999b4((double)FLOAT_803e52a8,param_1,0xff,0x28);
        }
        else {
          *(undefined2 *)(param_2 + 0x13c) = 0x119;
          FUN_800999b4((double)FLOAT_803e52a8,param_1,6,0x28);
        }
        *(undefined2 *)(param_2 + 0x13e) = 0;
        *(float *)(param_2 + 0x140) = FLOAT_803e52ac;
        FUN_800378c4(iVar3,0x7000a,param_1,param_2 + 0x13c);
        if (*(short *)(param_3 + 0x1a) != -1) {
          FUN_800200e8((int)*(short *)(param_3 + 0x1a),1);
        }
        *(undefined *)(param_2 + 0x136) = 8;
        FUN_800200e8(0x12e,1);
      }
    }
    else {
      FUN_80035e48(param_1,1);
      (**(code **)(*DAT_803dca78 + 0x14))(param_1);
      *(undefined *)(param_2 + 0x136) = 0;
      *(byte *)(param_2 + 0x137) = *(byte *)(param_2 + 0x137) & 0xef;
    }
  }
  iVar3 = (int)*(short *)(&DAT_80326bd0 + (uint)*(byte *)(param_2 + 0x136) * 2);
  if ((param_1[0x50] != iVar3) && (iVar3 != -1)) {
    FUN_80030334((double)FLOAT_803e52b0,param_1,iVar3,0);
  }
  iVar3 = FUN_8002fa48((double)*(float *)(&DAT_80326be8 + (uint)*(byte *)(param_2 + 0x136) * 4),
                       (double)FLOAT_803db414,param_1,local_4c);
  if (iVar3 == 0) {
    *(byte *)(param_2 + 0x137) = *(byte *)(param_2 + 0x137) & 0xfe;
  }
  else {
    *(byte *)(param_2 + 0x137) = *(byte *)(param_2 + 0x137) | 1;
  }
  if (*(char *)(param_2 + 0x136) == '\x01') {
    dVar10 = (double)(*(float *)(param_2 + 0x110) * local_4c[0] * FLOAT_803db418);
  }
  else if (*(char *)(param_2 + 0x136) == '\x05') {
    dVar10 = (double)(local_44 * FLOAT_803db418);
  }
  else {
    dVar10 = (double)FLOAT_803e5288;
  }
  if ((double)FLOAT_803e5288 == dVar10) {
    *(byte *)(param_2 + 0x137) = *(byte *)(param_2 + 0x137) & 0xf7;
  }
  else {
    *(byte *)(param_2 + 0x137) = *(byte *)(param_2 + 0x137) | 8;
  }
  uStack44 = (int)*(short *)(param_2 + 0x130) ^ 0x80000000;
  local_30 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e52b4 *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               DOUBLE_803e52c8)) / FLOAT_803e52b8));
  *(float *)(param_1 + 0x12) = (float)(dVar10 * dVar8);
  uStack36 = (int)*(short *)(param_2 + 0x130) ^ 0x80000000;
  local_28 = 0x43300000;
  dVar8 = (double)FUN_80294204((double)((FLOAT_803e52b4 *
                                        (float)((double)CONCAT44(0x43300000,uStack36) -
                                               DOUBLE_803e52c8)) / FLOAT_803e52b8));
  *(float *)(param_1 + 0x16) = (float)(dVar10 * dVar8);
  FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),(double)FLOAT_803e5288,
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

