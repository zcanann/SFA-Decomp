#include "ghidra_import.h"
#include "main/dll/NW/NWsfx.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern int FUN_80010340();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern int FUN_80021884();
extern uint FUN_80022264();
extern undefined4 FUN_8002ba34();
extern int FUN_8002bac4();
extern int FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035f28();
extern undefined4 FUN_80035f40();
extern undefined4 FUN_800379bc();
extern undefined8 FUN_80099c40();
extern undefined2 FUN_801d188c();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4 DAT_80327810;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e5f58;
extern f64 DOUBLE_803e5f60;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e5f20;
extern f32 FLOAT_803e5f24;
extern f32 FLOAT_803e5f28;
extern f32 FLOAT_803e5f2c;
extern f32 FLOAT_803e5f30;
extern f32 FLOAT_803e5f34;
extern f32 FLOAT_803e5f38;
extern f32 FLOAT_803e5f3c;
extern f32 FLOAT_803e5f40;
extern f32 FLOAT_803e5f44;
extern f32 FLOAT_803e5f48;

/*
 * --INFO--
 *
 * Function: FUN_801d0e2c
 * EN v1.0 Address: 0x801D083C
 * EN v1.0 Size: 2720b
 * EN v1.1 Address: 0x801D0E2C
 * EN v1.1 Size: 2656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0e2c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,float *param_10,int param_11,float *param_12,undefined4 param_13,
                 undefined4 param_14,int param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  undefined2 uVar4;
  uint uVar3;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  undefined auStack_68 [4];
  undefined auStack_64 [12];
  float local_58;
  float local_54;
  undefined4 local_50;
  float local_4c;
  float local_44;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar2 = FUN_8002bac4();
  if ((*(byte *)((int)param_10 + 0x137) & 4) != 0) {
    *(undefined *)((int)param_10 + 0x136) = 6;
  }
  dVar6 = (double)FLOAT_803dc078;
  dVar7 = (double)(float)(dVar6 * (double)(param_10[0x43] - param_10[0x42]));
  switch(*(char *)((int)param_10 + 0x136)) {
  case '\0':
    if ((*(byte *)((int)param_10 + 0x137) & 0x10) == 0) {
      iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_68);
      if (iVar2 == 0) {
        dVar6 = (double)param_10[0x42];
        uStack_2c = (uint)*(byte *)(param_11 + 0x19);
        local_30 = 0x43300000;
        if ((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5f58) <= dVar6) {
          uStack_2c = (uint)*(byte *)(param_11 + 0x1f);
          local_30 = 0x43300000;
          if (dVar6 < (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5f58)) {
            *(undefined *)((int)param_10 + 0x136) = 3;
          }
        }
        else {
          if ((*(byte *)((int)param_10 + 0x137) & 2) == 0) {
            uVar4 = FUN_801d188c();
            *(undefined2 *)(param_10 + 0x4c) = uVar4;
          }
          else {
            dVar7 = (double)(param_10[0x46] * param_10[0x46]);
            while( true ) {
              param_3 = (double)(param_10[0x1a] - *(float *)(param_9 + 6));
              dVar6 = (double)(param_10[0x1c] - *(float *)(param_9 + 10));
              if (dVar7 <= (double)(float)(param_3 * param_3 + (double)(float)(dVar6 * dVar6)))
              break;
              iVar2 = FUN_80010340((double)param_10[0x48],param_10);
              if ((iVar2 != 0) || (param_10[4] != 0.0)) {
                (**(code **)(*DAT_803dd71c + 0x90))(param_10);
              }
            }
            dVar6 = -dVar6;
            iVar2 = FUN_80021884();
            *(short *)(param_10 + 0x4c) = (short)iVar2;
          }
          *(undefined *)((int)param_10 + 0x136) = 1;
          FUN_8000bb38((uint)param_9,0xa0);
          *param_9 = *(short *)(param_10 + 0x4c) + -0x4000;
        }
      }
      else {
        fVar1 = param_10[0x4b] - FLOAT_803dc074;
        param_10[0x4b] = fVar1;
        if (fVar1 <= FLOAT_803e5f20) {
          if ((param_9[0x58] & 0x800U) != 0) {
            local_58 = *(float *)(param_9 + 0xc);
            local_54 = FLOAT_803e5f24 + *(float *)(param_9 + 0xe);
            local_50 = *(undefined4 *)(param_9 + 0x10);
            param_12 = (float *)0x200001;
            param_13 = 0xffffffff;
            param_14 = 0;
            param_15 = *DAT_803dd708;
            (**(code **)(param_15 + 8))(param_9,0x7f0,auStack_64);
          }
          param_10[0x4b] = FLOAT_803e5f28;
        }
      }
    }
    else {
      *(undefined *)((int)param_10 + 0x136) = 9;
    }
    break;
  case '\x01':
    if ((*(byte *)((int)param_10 + 0x137) & 0x10) == 0) {
      if ((*(byte *)((int)param_10 + 0x137) & 1) != 0) {
        *(undefined *)((int)param_10 + 0x136) = 0;
      }
    }
    else {
      *(undefined *)((int)param_10 + 0x136) = 9;
    }
    break;
  case '\x03':
  case '\a':
    if ((*(byte *)((int)param_10 + 0x137) & 0x10) != 0) {
      *(undefined *)((int)param_10 + 0x136) = 9;
      break;
    }
    if ((*(byte *)((int)param_10 + 0x137) & 1) != 0) {
      if (*(char *)((int)param_10 + 0x136) == '\x03') {
        *(undefined *)((int)param_10 + 0x136) = 4;
      }
      else {
        *(undefined *)((int)param_10 + 0x136) = 0;
      }
      break;
    }
  case '\x04':
    if ((*(byte *)((int)param_10 + 0x137) & 0x10) == 0) {
      iVar2 = FUN_80021884();
      *param_9 = (short)iVar2;
      param_3 = (double)param_10[0x42];
      dVar6 = (double)FLOAT_803e5f2c;
      uStack_2c = (uint)*(byte *)(param_11 + 0x1f);
      local_30 = 0x43300000;
      if (param_3 <=
          (double)(float)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                                 DOUBLE_803e5f58))) {
        uStack_2c = (uint)*(byte *)(param_11 + 0x19);
        local_30 = 0x43300000;
        if (param_3 < (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5f58)) {
          FUN_8000bb38((uint)param_9,0xa0);
          if (dVar7 < (double)FLOAT_803e5f30) {
            if ((*(byte *)((int)param_10 + 0x137) & 2) == 0) {
              uVar4 = FUN_801d188c();
              *(undefined2 *)(param_10 + 0x4c) = uVar4;
            }
            else {
              dVar7 = (double)(param_10[0x47] * param_10[0x47]);
              while( true ) {
                param_3 = (double)(param_10[0x1a] - *(float *)(param_9 + 6));
                dVar6 = (double)(param_10[0x1c] - *(float *)(param_9 + 10));
                if (dVar7 <= (double)(float)(param_3 * param_3 + (double)(float)(dVar6 * dVar6)))
                break;
                iVar2 = FUN_80010340((double)param_10[0x48],param_10);
                if ((iVar2 != 0) || (param_10[4] != 0.0)) {
                  (**(code **)(*DAT_803dd71c + 0x90))(param_10);
                }
              }
              dVar6 = -dVar6;
              iVar2 = FUN_80021884();
              *(short *)(param_10 + 0x4c) = (short)iVar2;
            }
            *(undefined *)((int)param_10 + 0x136) = 5;
            *param_9 = *(short *)(param_10 + 0x4c);
          }
          else {
            if ((*(byte *)((int)param_10 + 0x137) & 2) == 0) {
              uVar4 = FUN_801d188c();
              *(undefined2 *)(param_10 + 0x4c) = uVar4;
            }
            else {
              dVar7 = (double)(param_10[0x46] * param_10[0x46]);
              while( true ) {
                param_3 = (double)(param_10[0x1a] - *(float *)(param_9 + 6));
                dVar6 = (double)(param_10[0x1c] - *(float *)(param_9 + 10));
                if (dVar7 <= (double)(float)(param_3 * param_3 + (double)(float)(dVar6 * dVar6)))
                break;
                iVar2 = FUN_80010340((double)param_10[0x48],param_10);
                if ((iVar2 != 0) || (param_10[4] != 0.0)) {
                  (**(code **)(*DAT_803dd71c + 0x90))(param_10);
                }
              }
              dVar6 = -dVar6;
              iVar2 = FUN_80021884();
              *(short *)(param_10 + 0x4c) = (short)iVar2;
            }
            *(undefined *)((int)param_10 + 0x136) = 1;
            *param_9 = *(short *)(param_10 + 0x4c) + -0x4000;
          }
        }
      }
      else {
        *(undefined *)((int)param_10 + 0x136) = 7;
      }
    }
    else {
      *(undefined *)((int)param_10 + 0x136) = 9;
    }
    break;
  case '\x05':
    if ((*(byte *)((int)param_10 + 0x137) & 0x11) == 0x11) {
      *(undefined *)((int)param_10 + 0x136) = 9;
    }
    param_3 = (double)param_10[0x42];
    dVar6 = (double)FLOAT_803e5f2c;
    uStack_2c = (uint)*(byte *)(param_11 + 0x19);
    local_30 = 0x43300000;
    if ((param_3 <=
         (double)(float)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                                DOUBLE_803e5f58))) ||
       ((*(byte *)((int)param_10 + 0x137) & 1) == 0)) {
      if ((double)FLOAT_803e5f30 <= dVar7) {
        if ((*(byte *)((int)param_10 + 0x137) & 2) == 0) {
          uVar4 = FUN_801d188c();
          *(undefined2 *)(param_10 + 0x4c) = uVar4;
        }
        else {
          dVar7 = (double)(param_10[0x46] * param_10[0x46]);
          while( true ) {
            param_3 = (double)(param_10[0x1a] - *(float *)(param_9 + 6));
            dVar6 = (double)(param_10[0x1c] - *(float *)(param_9 + 10));
            if (dVar7 <= (double)(float)(param_3 * param_3 + (double)(float)(dVar6 * dVar6))) break;
            iVar2 = FUN_80010340((double)param_10[0x48],param_10);
            if ((iVar2 != 0) || (param_10[4] != 0.0)) {
              (**(code **)(*DAT_803dd71c + 0x90))(param_10);
            }
          }
          dVar6 = -dVar6;
          iVar2 = FUN_80021884();
          *(short *)(param_10 + 0x4c) = (short)iVar2;
        }
        *(undefined *)((int)param_10 + 0x136) = 1;
        FUN_8000bb38((uint)param_9,0xa0);
        *param_9 = *(short *)(param_10 + 0x4c) + -0x4000;
      }
    }
    else {
      *(undefined *)((int)param_10 + 0x136) = 4;
    }
    break;
  case '\x06':
    if ((*(byte *)((int)param_10 + 0x137) & 0x10) != 0) {
      *(undefined *)((int)param_10 + 0x136) = 9;
    }
    break;
  case '\t':
    FUN_80035f28((int)param_9,1);
    FUN_8000da78((uint)param_9,0x9b);
    if (param_10[0x49] <= FLOAT_803e5f20) {
      uStack_2c = FUN_80022264(0xf0,300);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      param_10[0x49] = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5f60);
    }
    fVar1 = param_10[0x49] - FLOAT_803dc074;
    param_10[0x49] = fVar1;
    dVar6 = (double)FLOAT_803e5f20;
    if (dVar6 < (double)fVar1) {
      fVar1 = param_10[0x4a] - FLOAT_803dc074;
      param_10[0x4a] = fVar1;
      if ((double)fVar1 <= dVar6) {
        local_58 = FLOAT_803e5f2c;
        local_54 = FLOAT_803e5f34;
        if ((param_9[0x58] & 0x800U) != 0) {
          param_12 = (float *)0x2;
          param_13 = 0xffffffff;
          param_14 = 0;
          param_15 = *DAT_803dd708;
          (**(code **)(param_15 + 8))(param_9,0x51d,auStack_64);
        }
        param_10[0x4a] = FLOAT_803e5f38;
      }
      uVar3 = FUN_80020078(0x12e);
      if (((uVar3 == 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) &&
         (dVar7 = (double)FUN_80021754((float *)(iVar2 + 0x18),(float *)(param_9 + 0xc)),
         dVar7 < (double)FLOAT_803e5f3c)) {
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
        if (param_9[0x23] == 0x658) {
          *(undefined2 *)(param_10 + 0x4f) = 0x18a;
          uVar5 = FUN_80099c40((double)FLOAT_803e5f40,param_9,0xff,0x28);
        }
        else {
          *(undefined2 *)(param_10 + 0x4f) = 0x119;
          uVar5 = FUN_80099c40((double)FLOAT_803e5f40,param_9,6,0x28);
        }
        *(undefined2 *)((int)param_10 + 0x13e) = 0;
        param_10[0x50] = FLOAT_803e5f44;
        param_12 = param_10 + 0x4f;
        FUN_800379bc(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x7000a,
                     (uint)param_9,(uint)param_12,param_13,param_14,param_15,param_16);
        if ((int)*(short *)(param_11 + 0x1a) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(param_11 + 0x1a),1);
        }
        *(undefined *)((int)param_10 + 0x136) = 8;
        FUN_800201ac(0x12e,1);
      }
    }
    else {
      FUN_80035f40((int)param_9,1);
      (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
      *(undefined *)((int)param_10 + 0x136) = 0;
      *(byte *)((int)param_10 + 0x137) = *(byte *)((int)param_10 + 0x137) & 0xef;
    }
  }
  iVar2 = (int)*(short *)(&DAT_80327810 + (uint)*(byte *)((int)param_10 + 0x136) * 2);
  if ((param_9[0x50] != iVar2) && (iVar2 != -1)) {
    FUN_8003042c((double)FLOAT_803e5f48,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,iVar2,0,param_12,param_13,param_14,param_15,param_16);
  }
  iVar2 = FUN_8002fb40((double)*(float *)((uint)*(byte *)((int)param_10 + 0x136) * 4 + -0x7fcd87d8),
                       (double)FLOAT_803dc074);
  if (iVar2 == 0) {
    *(byte *)((int)param_10 + 0x137) = *(byte *)((int)param_10 + 0x137) & 0xfe;
  }
  else {
    *(byte *)((int)param_10 + 0x137) = *(byte *)((int)param_10 + 0x137) | 1;
  }
  if (*(char *)((int)param_10 + 0x136) == '\x01') {
    dVar6 = (double)(param_10[0x44] * local_4c * FLOAT_803dc078);
  }
  else if (*(char *)((int)param_10 + 0x136) == '\x05') {
    dVar6 = (double)(local_44 * FLOAT_803dc078);
  }
  else {
    dVar6 = (double)FLOAT_803e5f20;
  }
  if ((double)FLOAT_803e5f20 == dVar6) {
    *(byte *)((int)param_10 + 0x137) = *(byte *)((int)param_10 + 0x137) & 0xf7;
  }
  else {
    *(byte *)((int)param_10 + 0x137) = *(byte *)((int)param_10 + 0x137) | 8;
  }
  uStack_2c = (int)*(short *)(param_10 + 0x4c) ^ 0x80000000;
  local_30 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  *(float *)(param_9 + 0x12) = (float)(dVar6 * dVar7);
  uStack_24 = (int)*(short *)(param_10 + 0x4c) ^ 0x80000000;
  local_28 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  *(float *)(param_9 + 0x16) = (float)(dVar6 * dVar7);
  FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),(double)FLOAT_803e5f20,
               (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
  return;
}
