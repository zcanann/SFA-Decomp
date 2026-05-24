#include "ghidra_import.h"
#include "main/dll/dll_131.h"

extern undefined4 FUN_800033a8();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3ce8;
extern f64 DOUBLE_803e3d00;
extern f64 DOUBLE_803e3d08;
extern f32 lbl_803DC074;
extern f32 lbl_803E3C74;
extern f32 lbl_803E3C8C;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CF8;

/*
 * --INFO--
 *
 * Function: FUN_80167764
 * EN v1.0 Address: 0x80167764
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801678A4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167764(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  uVar2 = 5;
  uVar3 = 1;
  uVar4 = 0x108;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)lbl_803E3CE0,param_9,param_10,iVar8);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  iVar7 = *(int *)(iVar8 + 0x40c);
  FUN_800033a8(iVar7,0,0x94);
  *(undefined *)(iVar7 + 0x90) = 5;
  *(byte *)(iVar7 + 0x92) = *(byte *)(iVar7 + 0x92) & 0xf | 0x30;
  fVar1 = lbl_803E3C74;
  dVar9 = (double)lbl_803E3C74;
  *(float *)(iVar7 + 0x7c) = lbl_803E3C74;
  *(float *)(iVar7 + 0x80) = lbl_803E3C8C;
  *(float *)(iVar7 + 0x84) = fVar1;
  *(float *)(iVar7 + 0x88) = -*(float *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x70) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(iVar7 + 0x74) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x78) = *(undefined4 *)(param_9 + 0x14);
  FUN_800305f8(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,uVar2,uVar3
               ,uVar4,uVar5,iVar6);
  *(ushort *)(iVar8 + 0x274) = (ushort)(*(char *)(param_10 + 0x2b) != '\0');
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined2 *)(iVar8 + 0x402) = 0;
  *(undefined *)(iVar8 + 0x405) = 0;
  *(undefined *)(iVar8 + 0x25f) = 0;
  ObjHits_DisableObject(param_9);
  fVar1 = lbl_803E3C8C;
  *(float *)(iVar7 + 4) = lbl_803E3C8C;
  *(float *)(iVar7 + 0x18) = fVar1;
  *(float *)(iVar7 + 0x2c) = fVar1;
  *(float *)(iVar7 + 0x40) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016793c
 * EN v1.0 Address: 0x8016793C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801679FC
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016793c(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,*(undefined4 *)(param_1 + 0xb8),2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167978
 * EN v1.0 Address: 0x80167978
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80167A8C
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167978(int param_1,float *param_2,byte *param_3)
{
  double dVar1;
  byte *pbVar2;
  
  dVar1 = DOUBLE_803e3ce8;
  pbVar2 = *(byte **)(param_1 + 0xb8);
  *param_2 = *(float *)(param_1 + 0x18) -
             (float)((double)CONCAT44(0x43300000,(uint)*pbVar2) - DOUBLE_803e3ce8);
  param_2[1] = *(float *)(param_1 + 0x18) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[1]) - dVar1);
  param_2[2] = *(float *)(param_1 + 0x20) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[2]) - dVar1);
  param_2[3] = *(float *)(param_1 + 0x20) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[3]) - dVar1);
  param_2[4] = *(float *)(param_1 + 0x1c) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[4]) - dVar1);
  param_2[5] = *(float *)(param_1 + 0x1c) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[5]) - dVar1);
  *param_3 = pbVar2[6];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167aa0
 * EN v1.0 Address: 0x80167AA0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80167B80
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167aa0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167ad4
 * EN v1.0 Address: 0x80167AD4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x80167C10
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80167ad4(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if ((*(short *)(param_2 + 0x274) == 2) &&
     (*(float *)(iVar3 + 0x34) = *(float *)(iVar3 + 0x34) - lbl_803DC074,
     *(float *)(iVar3 + 0x34) <= lbl_803E3CF8)) {
    *(undefined *)(param_2 + 0x346) = 1;
  }
  if ((*(char *)(param_2 + 0x346) != '\0') || (*(char *)(param_2 + 0x27b) != '\0')) {
    iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x3fe))
                                      - DOUBLE_803e3d00),param_1,param_2,1);
    if (iVar2 != 0) {
      return 5;
    }
    iVar2 = *(int *)(param_1 + 0x4c);
    uVar1 = randomGetRange(0,99);
    if ((int)uVar1 < (int)(uint)*(byte *)(iVar2 + 0x2f)) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,3);
    }
    else {
      uVar1 = randomGetRange(300,600);
      *(float *)(iVar3 + 0x34) =
           (f32)(s32)(uVar1);
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
    }
  }
  return 0;
}

#pragma scheduling off
#pragma peephole off
void fn_80167B60(int obj, int p)
{
  extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
  extern void fn_80169360(int obj, int n);
  extern int *gBaddieControlInterface;
  extern f32 lbl_803E3060;
  extern f32 lbl_803E3078;
  extern f32 lbl_803E3084;
  extern f32 lbl_803E3088;
  extern f32 lbl_803E308C;
  int b8;
  int b8_40c;

  b8 = *(int *)(obj + 0xb8);
  *(s8 *)(p + 0x34d) = 3;
  *(f32 *)(p + 0x2a0) = lbl_803E3084;
  {
    f32 fz = lbl_803E3060;
    *(f32 *)(p + 0x280) = fz;
    *(f32 *)(p + 0x284) = fz;
    if (*(char *)(p + 0x27a) != '\0') {
      ObjAnim_SetCurrentMove(obj, 5, fz, 0);
      *(s8 *)(p + 0x346) = 0;
    }
  }
  {
    u32 v = *(u32 *)(p + 0x314);
    if ((v & 0x1000) != 0) {
      *(u32 *)(p + 0x314) = v & ~0x1000;
      fn_80169360(obj, 2);
    }
  }
  b8_40c = *(int *)(b8 + 0x40c);
  if ((*(u8 *)(b8_40c + 0x4b) & 0x1) == 0) {
    Sfx_PlayFromObject(obj, 628);
    Sfx_PlayFromObject(obj, 631);
    Sfx_PlayFromObject(obj, 562);
    *(u8 *)(b8_40c + 0x4b) |= 0x1;
    {
      int r = 0;
      if (*(s16 *)(b8 + 0x3f0) != 0) {
        r = (int)(**(int (**)(int, int, int, int))(*(int *)(*gBaddieControlInterface) + 0x4c))(obj, 6, -1, 0);
      }
      if (r != 0) {
        f32 fz = lbl_803E3060;
        (**(void (**)(int, f32, f32, f32))(*(int *)(*(int *)(r + 0x68)) + 0x2c))(r, fz, lbl_803E3078, fz);
      }
    }
  }
  if ((*(u8 *)(b8_40c + 0x4b) & 0x2) == 0) {
    if (*(f32 *)(obj + 0x98) > lbl_803E3088) {
      Sfx_PlayFromObject(obj, 563);
      *(u8 *)(b8_40c + 0x4b) |= 0x2;
    }
  }
  *(u8 *)(obj + 0x36) = (u8)(s32)((lbl_803E3078 - *(f32 *)(obj + 0x98)) * lbl_803E308C);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3060;
extern f32 lbl_803E3080;
extern f32 timeDelta;
extern void** gPlayerInterface;

#pragma scheduling off
#pragma peephole off
int fn_80167A60(int* obj, u8* state) {
    f32* t = *(f32**)((char*)(*(int**)((char*)obj + 0xb8)) + 0x40c);
    if (*(s16*)((char*)state + 628) == 6) {
        f32 zero;
        f32 timer;
        if ((s8)state[635] != 0) {
            *(f32*)((char*)t + 0x44) = lbl_803E3080;
        }
        timer = *(f32*)((char*)t + 0x44);
        zero = lbl_803E3060;
        if (timer != zero) {
            *(f32*)((char*)t + 0x44) = timer - timeDelta;
            if (*(f32*)((char*)t + 0x44) < zero) {
                *(f32*)((char*)t + 0x44) = zero;
            }
        } else {
            return 6;
        }
    } else {
        if ((s8)state[838] != 0) return 6;
    }
    return 0;
}

int fn_80167AE4(int* obj, u8* state) {
    if (*(void**)((char*)state + 0x2d0) != NULL) {
        if ((s8)state[635] != 0) {
            f32 fz = lbl_803E3060;
            *(f32*)((char*)state + 0x284) = fz;
            *(f32*)((char*)state + 0x280) = fz;
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, state, 0);
        } else if ((s8)state[838] != 0) {
            return 6;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80167988(int obj, int p2)
{
  extern void ObjHits_DisableObject(int);
  extern void Obj_FreeObject(int);
  extern f32 lbl_803E3078;
  extern f32 lbl_803E307C;
  int sub = *(int *)(obj + 0xb8);

  if ((s32)(s8)*(u8 *)(p2 + 0x27b) != 0) {
    *(u8 *)(*(int *)(sub + 0x40c) + 0x4b) = 0;
    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 7);
    ObjHits_DisableObject(obj);
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x8);
    *(u16 *)(sub + 0x400) = (u16)(*(u16 *)(sub + 0x400) | 0x20);
    *(f32 *)(sub + 0x3e8) = lbl_803E3078;
    *(f32 *)(sub + 0x3ec) = lbl_803E307C;
  } else if ((s32)(s8)*(u8 *)(p2 + 0x346) != 0) {
    if (*(void **)(obj + 0x4c) == NULL) {
      Obj_FreeObject(obj);
      return 0;
    }
    return 4;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
