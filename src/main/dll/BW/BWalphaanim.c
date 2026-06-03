#include "ghidra_import.h"
#include "main/dll/BW/BWalphaanim.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_8000680c();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a10();
extern undefined4 FUN_80017a80();
extern int FUN_80053c14();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801ea854();
extern uint FUN_801eb0c0();
extern undefined4 fn_801EAE4C();
extern undefined4 fn_801EB0D4();
extern undefined4 fn_801EB634();
extern void fn_801EC1AC(int obj,int state);
extern undefined4 FUN_801ec7a0();
extern undefined4 FUN_801ecd30();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80293130();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E6838;
extern f32 lbl_803E68B0;

/*
 * --INFO--
 *
 * Function: SnowBike_update
 * EN v1.0 Address: 0x801ED428
 * EN v1.0 Size: 1732b
 * EN v1.1 Address: 0x801EDA60
 * EN v1.1 Size: 1700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SnowBike_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  double dVar7;
  float fStack_108;
  float fStack_104;
  float local_100;
  float local_fc;
  float fStack_f8;
  float local_f4;
  float local_f0;
  float fStack_ec;
  short local_e8;
  short local_e6;
  short local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  short local_d0;
  short local_ce;
  short local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float afStack_b8 [16];
  float afStack_78 [16];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_9 + 0x56) == -1) {
    uVar3 = GameBit_Get(0x1fa);
    if (uVar3 != 0) {
      *(undefined *)(iVar6 + 0x420) = 0;
    }
    uVar3 = GameBit_Get(0x1fb);
    if (uVar3 != 0) {
      param_1 = FUN_80017a10((int)param_9,0x13);
    }
  }
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  param_9[1] = *(short *)(iVar6 + 0x41c);
  param_9[2] = *(short *)(iVar6 + 0x41e);
  if (((*(byte *)(iVar6 + 0x428) >> 2 & 1) == 0) &&
     (uVar3 = GameBit_Get((int)*(short *)(iVar6 + 0x44a)), uVar3 == 0)) {
    cVar5 = *(char *)(iVar6 + 0x421);
    if (cVar5 != '\x01') {
      if (cVar5 < '\x01') {
        if (-1 < cVar5) {
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          if ((*(byte *)((int)param_9 + 0xaf) & 4) == 0) {
            *(undefined *)(iVar6 + 0x420) = 0;
          }
          else {
            *(undefined *)(iVar6 + 0x420) = 1;
          }
          FUN_8000680c((int)param_9,0x57);
        }
      }
      else if (cVar5 < '\x03') {
        fn_801EAE4C(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6);
        if ((*(byte *)(iVar6 + 0x428) >> 1 & 1) == 0) {
          FUN_8011e868(0x10);
          FUN_8011e844(0x11);
          cVar5 = FUN_80006bd0(0);
          uStack_34 = (int)cVar5 ^ 0x80000000;
          local_38 = 0x43300000;
          *(float *)(iVar6 + 0x45c) =
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e6798);
          cVar5 = FUN_80006bc8(0);
          uStack_2c = (int)cVar5 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar4 = (int)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e6798);
          local_28 = (longlong)iVar4;
          *(char *)(iVar6 + 0x460) = (char)iVar4;
          uVar3 = FUN_80006c10(0);
          *(uint *)(iVar6 + 0x458) = uVar3;
          uVar3 = FUN_80006c00(0);
          *(uint *)(iVar6 + 0x450) = uVar3;
          uVar3 = FUN_80006bf8(0);
          *(uint *)(iVar6 + 0x454) = uVar3;
          uStack_1c = -(int)*(char *)(iVar6 + 0x460) ^ 0x80000000;
          local_20 = 0x43300000;
          uStack_14 = FUN_80017730();
          uStack_14 = uStack_14 & 0xffff;
          local_18 = 0x43300000;
          iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e68b8) /
                       lbl_803E68B0);
          local_10 = (longlong)iVar4;
          *(short *)(iVar6 + 0x44c) = (short)iVar4;
          *(float *)(iVar6 + 0x45c) = *(float *)(iVar6 + 0x45c) / lbl_803E6804;
          fVar1 = *(float *)(iVar6 + 0x45c);
          fVar2 = lbl_803E6808;
          if ((lbl_803E6808 <= fVar1) && (fVar2 = fVar1, lbl_803E6784 < fVar1)) {
            fVar2 = lbl_803E6784;
          }
          *(float *)(iVar6 + 0x45c) = fVar2;
          fn_801EC1AC((int)param_9,iVar6);
          FUN_801ecd30(param_9,iVar6);
          if (*(float *)(iVar6 + 0x3e4) == lbl_803E6780) {
            *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
            *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
            *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
          }
          else {
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                         (float *)(iVar6 + 0x47c));
            FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                         (float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - lbl_803DC074;
            if (*(float *)(iVar6 + 0x3e4) <= lbl_803E6780) {
              iVar4 = FUN_80053c14();
              if (iVar4 != 0) {
                FUN_80053c20((double)lbl_803E6780,0);
              }
              *(float *)(iVar6 + 0x3e4) = lbl_803E6780;
            }
          }
          local_dc = lbl_803E6780;
          local_d8 = lbl_803E6780;
          local_d4 = lbl_803E6780;
          local_e0 = lbl_803E6784;
          local_e8 = -*(short *)(iVar6 + 0x40e);
          local_e6 = -param_9[1];
          local_e4 = -param_9[2];
          FUN_8001774c(afStack_b8,(int)&local_e8);
          FUN_80017778((double)lbl_803E6780,
                       (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                       (double)lbl_803E6780,afStack_b8,&local_100,&fStack_108,&fStack_f8);
          local_100 = local_100 * *(float *)(iVar6 + 0x540);
          local_fc = lbl_803E6780;
          FUN_80247edc((double)lbl_803DC074,&local_100,&local_100);
          FUN_80247e94((float *)(iVar6 + 0x494),&local_100,(float *)(iVar6 + 0x494));
          *(float *)(iVar6 + 0x498) =
               *(float *)(iVar6 + 0x4b0) * lbl_803DC074 + *(float *)(iVar6 + 0x498);
          dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x548),(double)lbl_803DC074);
          *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
          dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x54c),(double)lbl_803DC074);
          *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
          FUN_801ec7a0((uint)param_9,iVar6);
          FUN_80017778((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                       (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                       (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),(float *)(param_9 + 0x16)
                      );
          FUN_80017a80((int)param_9);
        }
        else {
          uVar3 = FUN_801eb0c0(param_9,iVar6);
          if (uVar3 != 0) {
            fn_801EC1AC((int)param_9,iVar6);
            FUN_801ecd30(param_9,iVar6);
            if (*(float *)(iVar6 + 0x3e4) == lbl_803E6780) {
              *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
              *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
              *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
            }
            else {
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x464),
                           (float *)(iVar6 + 0x47c));
              FUN_80247edc((double)*(float *)(iVar6 + 0x3e0),(float *)(iVar6 + 0x494),
                           (float *)(iVar6 + 0x494));
              *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - lbl_803DC074;
              if (*(float *)(iVar6 + 0x3e4) <= lbl_803E6780) {
                iVar4 = FUN_80053c14();
                if (iVar4 != 0) {
                  FUN_80053c20((double)lbl_803E6780,0);
                }
                *(float *)(iVar6 + 0x3e4) = lbl_803E6780;
              }
            }
            local_c4 = lbl_803E6780;
            local_c0 = lbl_803E6780;
            local_bc = lbl_803E6780;
            local_c8 = lbl_803E6784;
            local_d0 = -*(short *)(iVar6 + 0x40e);
            local_ce = -param_9[1];
            local_cc = -param_9[2];
            FUN_8001774c(afStack_78,(int)&local_d0);
            FUN_80017778((double)lbl_803E6780,
                         (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                         (double)lbl_803E6780,afStack_78,&local_f4,&fStack_104,&fStack_ec);
            local_f4 = local_f4 * *(float *)(iVar6 + 0x540);
            local_f0 = lbl_803E6780;
            FUN_80247edc((double)lbl_803DC074,&local_f4,&local_f4);
            FUN_80247e94((float *)(iVar6 + 0x494),&local_f4,(float *)(iVar6 + 0x494));
            *(float *)(iVar6 + 0x498) =
                 *(float *)(iVar6 + 0x4b0) * lbl_803DC074 + *(float *)(iVar6 + 0x498);
            dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x548),(double)lbl_803DC074);
            *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
            dVar7 = (double)FUN_80293130((double)*(float *)(iVar6 + 0x54c),(double)lbl_803DC074);
            *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
            FUN_801ec7a0((uint)param_9,iVar6);
            FUN_80017778((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                         (double)*(float *)(iVar6 + 0x49c),(float *)(iVar6 + 0xec),
                         (float *)(param_9 + 0x12),(float *)(param_9 + 0x14),
                         (float *)(param_9 + 0x16));
            FUN_80017a80((int)param_9);
          }
        }
        fn_801EB0D4((uint)param_9,iVar6);
        uVar3 = (uint)(lbl_803E6838 * -*(float *)(iVar6 + 0x430));
        local_10 = (longlong)(int)uVar3;
        FUN_801ea854((double)*(float *)(iVar6 + 0x49c),(uint)param_9,iVar6,uVar3,iVar6 + 0x461,7);
        fn_801EB634((int)param_9,iVar6);
        *param_9 = *(short *)(iVar6 + 0x40e);
      }
    }
  }
  else {
    *(byte *)(iVar6 + 0x428) = *(byte *)(iVar6 + 0x428) & 0xfb | 4;
  }
  return;
}

extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;

#pragma scheduling off
#pragma peephole off
void SnowBike_release(void) {
    if (lbl_803DDC60 != 0) {
        textureFree(lbl_803DDC60);
        lbl_803DDC60 = 0;
    }
}
void SnowBike_initialise(void) {
    if (lbl_803DDC60 == 0) {
        lbl_803DDC60 = textureLoadAsset(0x186);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void SB_CloudRunner_onSeqFree(int *obj) {
    int *p = (int*)obj[0xb8/4];
    *(f32*)((char*)p + 0x4c) = *(f32*)((char*)obj + 0xc);
    *(f32*)((char*)p + 0x50) = *(f32*)((char*)obj + 0x10);
    *(f32*)((char*)p + 0x54) = *(f32*)((char*)obj + 0x14);
    {
        s32 v = *(s16*)obj - 0x4000;
        *(s16*)((char*)p + 0x2c) = (s16)v;
    }
    *(s16*)((char*)p + 0x2e) = *(s16*)((char*)obj + 4);
}
#pragma peephole reset

extern char lbl_803284E0[];
extern u32 lbl_803E5AE0;
extern u8 *mmAlloc(int size, int tag, int a);
extern void *memcpy(void *dst, const void *src, int n);
extern void Obj_ClearModelSlotIndex(int obj);
extern void fn_801EC928(int obj, u8 *state);
extern void fn_801EB420();
extern void ObjGroup_AddObject(int obj, int group);
extern void curves_setLocalPointCollisionEx(u8 *path, int a, u8 *b, f32 *c, int d, int e);
extern int *gGameUIInterface;
extern int *gPathControlInterface;
extern f32 lbl_803DC0B8;
extern f32 lbl_803DC0C0;
extern f32 lbl_803DC0C4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C54;
extern f32 lbl_803E5C58;
extern f32 lbl_803E5C5C;
extern f32 lbl_803E5C60;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;

typedef struct {
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;

void SnowBike_init(int obj, u8 *params, int flag)
{
    char *base = lbl_803284E0;
    u32 pathParam = lbl_803E5AE0;
    u8 *state = *(u8 **)(obj + 0xb8);
    u8 *alloc;
    u8 *path;
    int i;
    s16 rot;
    f32 fz;
    f32 fv;

    if (*(s8 *)(obj + 0xac) == 0x13) {
        alloc = mmAlloc(36, 5, 0);
        memcpy(alloc, params, 36);
        *(u8 **)(obj + 0x4c) = alloc;
        *(s16 *)(obj + 6) |= 0x2000;
        Obj_ClearModelSlotIndex(obj);
    }
    rot = params[0x18] << 8;
    *(s16 *)(state + 0x40c) = rot;
    *(s16 *)(state + 0x40e) = rot;
    *(s16 *)obj = rot;
    fn_801EC928(obj, state);
    if (flag == 0) {
        if (((SnowBikeFlags *)(state + 0x428))->b20) {
            *(f32 *)(state + 0x4b8) = lbl_803E5B90;
            *(f32 *)(state + 0x4c0) = lbl_803E5AEC;
            *(f32 *)(state + 0x4bc) = lbl_803E5B94;
            if (*(s8 *)(state + 0x421) == 2) {
                (**(void (**)(int, int))(*gGameUIInterface + 0x58))((int)*(f32 *)(state + 0x4b8), 1485);
                (**(void (**)(f32))(*gGameUIInterface + 0x68))(lbl_803E5B98);
            }
        }
    }
    if (params[0x19] != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b02 = 1;
    }
    *(int *)(state + 0x38) = -1;
    *(int *)(state + 0x3c) = -1;
    *(int *)(state + 0x40) = -1;
    state[0x5c] = params[0x1c];
    state[0x5d] = params[0x1d];
    *(f32 *)(state + 0xc) = *(f32 *)(obj + 0xc);
    *(f32 *)(state + 0x10) = *(f32 *)(obj + 0x10);
    *(f32 *)(state + 0x14) = *(f32 *)(obj + 0x14);
    *(int *)(obj + 0xbc) = (int)fn_801EB420;
    ObjGroup_AddObject(obj, 10);
    if (flag == 0) {
        i = 0;
        for (path = state; i < 9; i++) {
            *(u8 **)(path + 0x4c8) = mmAlloc(1600, 26, 0);
            path += 8;
        }
    }
    *(f32 *)(state + 0x51c) = *(f32 *)(obj + 0x18);
    *(f32 *)(state + 0x520) = *(f32 *)(obj + 0x1c);
    *(f32 *)(state + 0x524) = *(f32 *)(obj + 0x20);
    *(f32 *)(state + 0x68) = lbl_803E5AE8;
    *(s16 *)(state + 0x448) = *(s16 *)(params + 0x1a);
    *(s16 *)(state + 0x44a) = *(s16 *)(params + 0x1e);
    if (GameBit_Get(*(s16 *)(state + 0x44a)) != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b04 = 1;
    }
    *(f32 *)(state + 0x438) = lbl_803E5B1C;
    fz = lbl_803E5AE8;
    *(f32 *)(state + 0x3f4) = fz;
    *(f32 *)(state + 0x3f8) = fz;
    *(f32 *)(state + 0x18) = lbl_803E5C48;
    *(f32 *)(state + 0x1c) = fz;
    *(f32 *)(state + 0x20) = lbl_803E5BC4;
    *(f32 *)(state + 0x24) = lbl_803E5C50;
    *(s8 *)(state + 0x65) = -1;
    fv = lbl_803E5B98;
    *(f32 *)(state + 0x464) = fv;
    *(f32 *)(state + 0x468) = fv;
    *(s16 *)(state + 0x440) = 0x436;
    switch (*(s16 *)(obj + 0x46)) {
    case 0x72:
    default:
        state[0x434] = 1;
        *(f32 *)(state + 0x46c) = lbl_803E5C50;
        *(s16 *)(state + 0x440) = 282;
        break;
    case 0x16c:
        state[0x434] = 1;
        state[0x435] = 0;
        *(f32 *)(state + 0x1c) = lbl_803E5B14;
        *(f32 *)(state + 0x18) = lbl_803E5C54;
        *(s8 *)(state + 0x65) = 1;
        *(f32 *)(state + 0x46c) = lbl_803E5AF0;
        break;
    case 0x16f:
        state[0x434] = 1;
        state[0x58] = 1;
        state[0x435] = 1;
        *(s8 *)(state + 0x65) = 2;
        *(f32 *)(state + 0x46c) = lbl_803E5AF0;
        break;
    case 0x38c:
        state[0x434] = 0;
        *(f32 *)(state + 0x46c) = lbl_803DC0C4;
        *(s16 *)(state + 0x440) = 282;
        break;
    case 0x38d:
        state[0x434] = 0;
        state[0x435] = 0;
        *(f32 *)(state + 0x1c) = lbl_803E5B14;
        *(f32 *)(state + 0x18) = lbl_803E5C54;
        *(f32 *)(state + 0x46c) = lbl_803E5C58 * lbl_803DC0C0;
        break;
    case 0x38e:
        state[0x434] = 0;
        state[0x435] = 1;
        *(f32 *)(state + 0x1c) = lbl_803E5B48;
        *(f32 *)(state + 0x18) = lbl_803E5C5C;
        *(f32 *)(state + 0x46c) = lbl_803E5C60 * lbl_803DC0C0;
        break;
    case 0x4d4:
        state[0x434] = 0;
        state[0x435] = 2;
        *(f32 *)(state + 0x1c) = lbl_803E5B48;
        *(f32 *)(state + 0x18) = lbl_803E5C5C;
        *(f32 *)(state + 0x46c) = lbl_803DC0C0;
        break;
    }
    fv = *(f32 *)(state + 0x464);
    *(f32 *)(state + 0x47c) = fv;
    *(f32 *)(state + 0x470) = fv;
    fv = *(f32 *)(state + 0x468);
    *(f32 *)(state + 0x480) = fv;
    *(f32 *)(state + 0x474) = fv;
    fv = *(f32 *)(state + 0x46c);
    *(f32 *)(state + 0x484) = fv;
    *(f32 *)(state + 0x478) = fv;
    *(char **)(state + 0x60) = base + state[0x434] * 6 + 0xa4;
    if (state[0x434] == 0) {
        if (!((SnowBikeFlags *)(state + 0x428))->b02) {
            ((SnowBikeFlags *)(state + 0x428))->b20 = 1;
            *(f32 *)(state + 0x4c4) = lbl_803E5AE8;
        }
        *(f32 *)(state + 0x538) = lbl_803E5C64;
    } else {
        *(f32 *)(state + 0x538) = lbl_803E5B74;
    }
    path = state + 0x178;
    path[0x25b] = 1;
    (**(void (**)(u8 *, int, int, int))(*gPathControlInterface + 0x4))(path, 0, 0x48607, 1);
    (**(void (**)(u8 *, int, char *, char *, u32 *))(*gPathControlInterface + 0xc))(path, 4, base, base + 0x30, &pathParam);
    if (((SnowBikeFlags *)(state + 0x428))->b02 && *(s8 *)(state + 0x65) != -1) {
        curves_setLocalPointCollisionEx(path, 1, (u8 *)(base + 0x40), &lbl_803DC0B8, 8, *(s8 *)(state + 0x65));
    } else {
        (**(void (**)(u8 *, int, char *, f32 *, int))(*gPathControlInterface + 0x8))(path, 1, base + 0x40, &lbl_803DC0B8, 8);
    }
    path[0x264] = lbl_803E5C68 + lbl_803DC0B8;
    (**(void (**)(int, u8 *))(*gPathControlInterface + 0x20))(obj, path);
}
