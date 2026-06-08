#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/enemy_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/projswitch.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/objhits_types.h"
#include "main/resource.h"


extern undefined4 FUN_800033a8();
extern undefined4 FUN_800068c4();
extern int FUN_80006b7c();
extern int FUN_800175c4();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_8001789c();
extern undefined4 FUN_800178ac();
extern undefined4 FUN_800178b0();
extern byte FUN_80017a34();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern uint ObjGroup_ContainsObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern int FUN_8005b220();
extern int FUN_8005b398();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8011e800();
extern undefined8 FUN_8014721c();
extern undefined8 FUN_801476cc();
extern undefined4 FUN_8014ab58();
extern undefined8 FUN_8014c0b4();
extern undefined4 FUN_8014c528();
extern undefined4 FUN_8014c690();
extern undefined4 FUN_8014ff4c();
extern undefined4 FUN_8015209c();
extern undefined4 FUN_801529a4();
extern undefined4 FUN_80152ec0();
extern undefined4 FUN_80153358();
extern undefined4 FUN_80153a80();
extern undefined4 FUN_801540a0();
extern undefined4 FUN_80154a78();
extern undefined4 fn_80154C24();
extern void rachnopInit(undefined4 param_1,int param_2);
extern void baddieInit_80156188(undefined4 param_1,int param_2);
extern void wbInit(undefined4 param_1,int param_2);
extern undefined4 FUN_80157100();
extern undefined4 FUN_8015801c();
extern undefined4 FUN_801599e0();
extern undefined4 FUN_80159bd0();
extern undefined4 FUN_80159c3c();
extern undefined4 FUN_8015a31c();
extern undefined4 FUN_8015b218();
extern undefined4 FUN_8015b3d4();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_8031e828;
extern undefined4 DAT_8031e834;
extern undefined4 DAT_803dc8c0;
extern undefined4 DAT_803dc8c8;
extern undefined4 DAT_803dc8cc;
extern undefined4 DAT_803dc8d0;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e3218;
extern f64 DOUBLE_803e3278;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E3210;
extern f32 lbl_803E3244;
extern f32 lbl_803E324C;
extern f32 lbl_803E3284;
extern f32 lbl_803E3288;
extern f32 lbl_803E328C;
extern f32 lbl_803E3290;
extern f32 lbl_803E3294;
extern f32 lbl_803E3298;

/*
 * --INFO--
 *
 * Function: enemy_free
 * EN v1.0 Address: 0x8014D164
 * EN v1.0 Size: 620b
 * EN v1.1 Address: 0x8014D194
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d164(double param_1,double param_2,ushort *param_3,int param_4,uint param_5,
                 char param_6)
{
  uint uVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  undefined8 local_50;
  undefined8 local_48;
  
  dVar4 = (double)(lbl_803DC074 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e3278));
  if ((double)lbl_803E3200 < dVar4) {
    dVar4 = (double)lbl_803E3200;
  }
  uVar1 = FUN_80017730();
  local_50 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)*param_3 ^ 0x80000000);
  dVar2 = (double)(float)(local_50 - DOUBLE_803e3218);
  if ((double)lbl_803E324C < dVar2) {
    dVar2 = (double)(float)((double)lbl_803E3284 + dVar2);
  }
  if (dVar2 < (double)lbl_803E328C) {
    dVar2 = (double)(float)((double)lbl_803E3288 + dVar2);
  }
  dVar3 = (double)(float)(dVar2 * dVar4);
  *param_3 = *param_3 + (short)(int)(dVar2 * dVar4);
  if (param_1 != (double)lbl_803E31FC) {
    if (param_6 == '\0') {
      param_3[2] = (ushort)(int)(lbl_803DC078 * (float)(dVar3 * param_1));
      if ((short)param_3[2] < 0x2001) {
        if ((short)param_3[2] < -0x2000) {
          param_3[2] = 0xe000;
        }
      }
      else {
        param_3[2] = 0x2000;
      }
    }
    else {
      param_3[2] = param_3[2] + (short)(int)(param_1 * (double)(float)(dVar3 * dVar4));
    }
  }
  if ((double)lbl_803E31FC != param_2) {
    FUN_80293900((double)(*(float *)(param_4 + 0x2c0) * *(float *)(param_4 + 0x2c0) +
                         *(float *)(param_4 + 0x2b8) * *(float *)(param_4 + 0x2b8)));
    uVar1 = FUN_80017730();
    local_48 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)param_3[1] ^ 0x80000000);
    dVar2 = (double)(float)(local_48 - DOUBLE_803e3218);
    if ((double)lbl_803E324C < dVar2) {
      dVar2 = (double)(float)((double)lbl_803E3284 + dVar2);
    }
    if (dVar2 < (double)lbl_803E328C) {
      dVar2 = (double)(float)((double)lbl_803E3288 + dVar2);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar2 * dVar4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d3d0
 * EN v1.0 Address: 0x8014D3D0
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8014D3F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d3d0(short *param_1,undefined4 param_2,uint param_3,short param_4)
{
  float fVar1;
  short sVar2;
  int iVar3;
  
  iVar3 = FUN_80017730();
  sVar2 = (short)iVar3 - *param_1;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  fVar1 = lbl_803DC074 / (float)((double)CONCAT44(0x43300000,param_3 & 0xffff) - DOUBLE_803e3278);
  if (lbl_803E3200 < fVar1) {
    fVar1 = lbl_803E3200;
  }
  *param_1 = *param_1 +
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)(short)(sVar2 + param_4) ^ 0x80000000) -
                                 DOUBLE_803e3218) * fVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d4c8
 * EN v1.0 Address: 0x8014D4C8
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8014D504
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d4c8(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
                 uint param_11,uint param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)
{
  if ((double)lbl_803E31FC == param_1) {
    *(float *)(param_10 + 0x308) = lbl_803E3208;
  }
  else {
    param_2 = (double)lbl_803E3200;
    *(float *)(param_10 + 0x308) =
         (float)(param_2 / (double)(float)((double)lbl_803E3204 * param_1));
  }
  *(char *)(param_10 + 0x323) = (char)param_13;
  FUN_800305f8((double)lbl_803E31FC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,param_11 & 0xff,param_12,param_12,param_13,param_14,param_15,param_16);
  if (*(int *)(param_9 + 0x54) != 0) {
    (*(ObjHitsPriorityState **)(param_9 + 0x54))->suppressOutgoingHits = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d59c
 * EN v1.0 Address: 0x8014D59C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8014D584
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d59c(int param_1,undefined4 *param_2)
{
  if (((GameObject *)param_1)->anim.seqId == 0x7c8) {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)&((GameObject *)param_1)->extra + 0x36c),FUN_80159bd0);
  }
  else {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)&((GameObject *)param_1)->extra + 0x36c),(undefined *)0x0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d600
 * EN v1.0 Address: 0x8014D600
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8014D5F8
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d600(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  puVar5 = *(uint **)(iVar3 + 0xb8);
  if ((uint *)puVar5[0xdb] != (uint *)0x0) {
    FUN_800178b0((uint *)puVar5[0xdb]);
  }
  if (puVar5[0xda] != 0) {
    FUN_80017620(puVar5[0xda]);
    puVar5[0xda] = 0;
  }
  if (*puVar5 != 0) {
    FUN_80017814(*puVar5);
    *puVar5 = 0;
  }
  sVar2 = *(short *)(iVar3 + 0x46);
  if (sVar2 == 0x851) {
    uVar4 = ObjGroup_ContainsObject(iVar3,0x50);
    if (uVar4 != 0) {
      ObjGroup_RemoveObject(iVar3,0x50);
    }
  }
  else if ((sVar2 < 0x851) && (sVar2 == 0x7c8)) {
    FUN_80159c3c(iVar3);
  }
  bVar1 = *(byte *)(iVar3 + 0xeb);
  for (iVar6 = 0; iVar6 < (int)(uint)bVar1; iVar6 = iVar6 + 1) {
    iVar7 = *(int *)(iVar3 + 200);
    if ((iVar7 != 0) &&
       ((uVar8 = ObjLink_DetachChild(iVar3,iVar7), (int)uVar9 == 0 ||
        ((*(ushort *)(iVar7 + 0xb0) & 0x10) == 0)))) {
      FUN_80017ac8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7);
    }
  }
  (*gExpgfxInterface)->freeSource(iVar3);
  ObjGroup_RemoveObject(iVar3,3);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d7b8
 * EN v1.0 Address: 0x8014D7B8
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x8014D730
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d7b8(uint param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  if ((visible != 0) && (((GameObject *)param_1)->unkF4 == 0)) {
    FUN_8003b818(param_1);
    uVar1 = *(uint *)(iVar3 + 0x2e8);
    if ((uVar1 & 3) != 0) {
      if ((uVar1 & 1) != 0) {
        *(uint *)(iVar3 + 0x2e8) = uVar1 & ~1;
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 2;
      }
      if (((EnemyState *)iVar3)->modelLight == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)&((EnemyState *)iVar3)->modelLight = piVar2;
      }
      FUN_8008111c((double)lbl_803E3200,(double)*(float *)(iVar3 + 0x30c),param_1,3,
                   *(int **)&((EnemyState *)iVar3)->modelLight);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 4) != 0) {
      if (((EnemyState *)iVar3)->modelLight == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)&((EnemyState *)iVar3)->modelLight = piVar2;
      }
      FUN_8008111c((double)lbl_803E3200,(double)*(float *)(iVar3 + 0x30c),param_1,4,
                   *(int **)&((EnemyState *)iVar3)->modelLight);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x40) != 0) {
      FUN_800068c4(param_1,0x9e);
      FUN_8008111c((double)lbl_803E3200,(double)*(float *)(iVar3 + 0x30c),param_1,5,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x80) != 0) {
      FUN_800068c4(param_1,0x9e);
      FUN_8008111c((double)lbl_803E3290,(double)*(float *)(iVar3 + 0x30c),param_1,6,(int *)0x0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x100) != 0) {
      FUN_8008111c((double)lbl_803E3294,(double)*(float *)(iVar3 + 0x30c),param_1,7,(int *)0x0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d924
 * EN v1.0 Address: 0x8014D924
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8014D8C4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d924(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_1)->extra;
  if ((*(int *)(iVar2 + 0x368) != 0) && (iVar1 = FUN_800175c4(*(int *)(iVar2 + 0x368)), iVar1 == 0))
  {
    FUN_80017620(*(uint *)(iVar2 + 0x368));
    *(undefined4 *)(iVar2 + 0x368) = 0;
  }
  ((EnemyState *)iVar2)->lastHitObject = (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->lastHitObject;
  if ((*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->lastHitObject != 0) {
    (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->suppressOutgoingHits = 1;
  }
  if (((*(int *)&((GameObject *)param_1)->unkC8 != 0) &&
      (iVar1 = *(int *)(*(int *)&((GameObject *)param_1)->unkC8 + 0x54), iVar1 != 0)) &&
     (((ObjHitsPriorityState *)iVar1)->lastHitObject != 0)) {
    (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->suppressOutgoingHits = 1;
  }
  if (((EnemyState *)iVar2)->unk36C != 0) {
    FUN_800178ac(((EnemyState *)iVar2)->unk36C);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: enemy_init
 * EN v1.0 Address: 0x8014D9E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014D984
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8014d9e8
 * EN v1.0 Address: 0x8014D9E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014DE78
 * EN v1.1 Size: 1932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014d9e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,int param_11)
{
}

/* conditional init/free pair. */
extern void *lbl_803DDA50;
#pragma scheduling off
#pragma peephole off
void enemy_release(void) { if (lbl_803DDA50 != NULL) { Resource_Release(lbl_803DDA50); lbl_803DDA50 = NULL; } }
void enemy_initialise(void) { if (lbl_803DDA50 == NULL) lbl_803DDA50 = Resource_Acquire(0x5a, 1); }
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E256C;
extern f32 lbl_803E25F8;
extern f32 lbl_803E25FC;
extern void objRenderFn_8003b8f4(f32 f);
extern int objCreateLight(int a, int b);
extern void objParticleFn_80099d84(int *obj, f32 f, int kind, f32 scale, int light);
extern void Sfx_KeepAliveLoopedObjectSound(int *obj, int id);

#pragma scheduling off
#pragma peephole off
void enemy_render(int *obj, int p2, int p3, int p4, int p5, s8 visible) {
    int *state = ((GameObject *)obj)->extra;
    if (visible != 0) {
        if (((GameObject *)obj)->unkF4 == 0) {
            ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E256C);
            {
                u32 flags = *(u32 *)((char *)state + 0x2e8);
                if ((flags & 3) != 0) {
                    if ((flags & 1) != 0) {
                        *(u32 *)((char *)state + 0x2e8) = flags & ~1;
                        *(u32 *)((char *)state + 0x2e8) = *(u32 *)((char *)state + 0x2e8) | 2;
                    }
                    if (*(void **)((char *)state + 0x368) == NULL) {
                        *(int *)((char *)state + 0x368) = objCreateLight(0, 1);
                    }
                    objParticleFn_80099d84(obj, lbl_803E256C, 3, *(f32 *)((char *)state + 0x30c),
                                           *(int *)((char *)state + 0x368));
                }
            }
            if ((*(u32 *)((char *)state + 0x2e8) & 4) != 0) {
                if (*(void **)((char *)state + 0x368) == NULL) {
                    *(int *)((char *)state + 0x368) = objCreateLight(0, 1);
                }
                objParticleFn_80099d84(obj, lbl_803E256C, 4, *(f32 *)((char *)state + 0x30c),
                                       *(int *)((char *)state + 0x368));
            }
    if ((*(u32 *)((char *)state + 0x2e8) & 0x40) != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
        objParticleFn_80099d84(obj, lbl_803E256C, 5, *(f32 *)((char *)state + 0x30c), 0);
    }
    if ((*(u32 *)((char *)state + 0x2e8) & 0x80) != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
        objParticleFn_80099d84(obj, lbl_803E25F8, 6, *(f32 *)((char *)state + 0x30c), 0);
    }
    if ((*(u32 *)((char *)state + 0x2e8) & 0x100) != 0) {
        objParticleFn_80099d84(obj, lbl_803E25FC, 7, *(f32 *)((char *)state + 0x30c), 0);
    }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int modelLightStruct_getActiveState(int light);
extern void ModelLightStruct_free(int light);
extern void fn_80026C54(int p);

#pragma scheduling off
#pragma peephole off
void enemy_hitDetect(int obj)
{
    u8 *state = ((GameObject *)obj)->extra;

    if (*(void **)(state + 0x368) != NULL && modelLightStruct_getActiveState(((EnemyState *)state)->modelLight) == 0) {
        ModelLightStruct_free(((EnemyState *)state)->modelLight);
        ((EnemyState *)state)->modelLight = 0;
    }
    ((EnemyState *)state)->lastHitObject = (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject;
    if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0) {
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (((GameObject *)obj)->unkC8 != NULL && *(void **)(*(int *)&((GameObject *)obj)->unkC8 + 0x54) != NULL
        && (*(ObjHitsPriorityState **)(*(int *)&((GameObject *)obj)->unkC8 + 0x54))->lastHitObject != 0) {
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (*(void **)(state + 0x36c) != NULL) {
        fn_80026C54(((EnemyState *)state)->unk36C);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80026C88(int p);
extern void mm_free(int p);
extern void smallbasket_stopLoopSfx(int obj, u8 *state);
extern void Obj_FreeObject(int obj);

#pragma scheduling off
#pragma peephole off
void enemy_free(int obj, int flag)
{
    u8 *child;
    int i;
    u8 *state;
    int n;

    state = ((GameObject *)obj)->extra;

    if (*(void **)(state + 0x36c) != NULL) {
        fn_80026C88(((EnemyState *)state)->unk36C);
    }
    if (*(void **)(state + 0x368) != NULL) {
        ModelLightStruct_free(((EnemyState *)state)->modelLight);
        ((EnemyState *)state)->modelLight = 0;
    }
    if (*(void **)state != NULL) {
        mm_free(*(int *)state);
        *(int *)state = 0;
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x7c8:
        smallbasket_stopLoopSfx(obj, state);
        break;
    case 0x851:
        if ((int)ObjGroup_ContainsObject(obj, 0x50) != 0) {
            ObjGroup_RemoveObject(obj, 0x50);
        }
        break;
    }
    n = ((GameObject *)obj)->unkEB;
    for (i = 0; i < n; i++) {
        child = ((GameObject *)obj)->unkC8;
        if (child != NULL) {
            ObjLink_DetachChild(obj, child);
            if (flag == 0 || (*(u16 *)(child + 0xb0) & 0x10) == 0) {
                Obj_FreeObject((int)child);
            }
        }
    }
    (*gExpgfxInterface)->freeSource(obj);
    ObjGroup_RemoveObject(obj, 3);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 *getTrickyObject(void);
extern u8 *Obj_GetPlayerObject(void);
extern uint GameBit_Get(int bit);
extern int getCurUiDll(void);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int isInBounds(f32 x, f32 z);
extern int objIsFrozen(int obj);
extern void baddie_updateWhileFrozen(int obj, u8 *state, int flag);
extern void baddieInstantiateWeapon(int obj, u8 *state);
extern f32 vec3f_distanceSquared(f32 *a, f32 *b);
extern void hudFn_8011f38c(int a);
extern void fn_8014BC98(int obj, u8 *state);
extern void fn_8014B878(int obj, u8 *state);
extern void objAnimFn_8014a9f0(int obj, u8 *state);
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern MapEventInterface **gMapEventInterface;
extern f32 lbl_803E2574;
extern f32 lbl_803E2600;


#pragma scheduling off
#pragma peephole off
void enemy_update(int obj)
{
    u8 *player;
    u8 *state;
    u8 *setup;
    u8 *tricky;
    u32 flags;
    u8 *s2;
    f32 fz;

    state = ((GameObject *)obj)->extra;
    setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    tricky = getTrickyObject();
    if (getCurUiDll() == 4) {
        return;
    }
    if ((((EnemyState *)state)->flags2E4 & 0x8000006) != 0) {
        if (objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ) == -1) {
            return;
        }
    } else {
        if (isInBounds(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosZ) == 0) {
            return;
        }
    }
    if (objIsFrozen(obj) != 0) {
        baddie_updateWhileFrozen(obj, state, 1);
        return;
    }
    if (*(void **)(state + 0x29c) == NULL) {
        ((EnemyState *)state)->trackedObj = Obj_GetPlayerObject();
    } else if ((*(u16 *)(*(int *)(state + 0x29c) + 0xb0) & 0x40) != 0) {
        ((EnemyState *)state)->trackedObj = Obj_GetPlayerObject();
    }
    ((EnemyState *)state)->initialFlags = *(int *)(state + 0x2dc);
    baddieInstantiateWeapon(obj, state);
    flags = ((EnemyState *)state)->controlFlags;
    if ((flags & 1) != 0 && (flags & 2) == 0) {
        if (*(s8 *)(setup + 0x2e) == -1) {
            return;
        }
        if (setup != NULL && (setup[0x2b] & 8) != 0) {
            ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)setup)->posX;
            ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
            ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)setup)->posZ;
        }
        (*gObjectTriggerInterface)->runSequence(*(s8 *)(setup + 0x2e), (void *)obj, -1);
        ((EnemyState *)state)->controlFlags |= 2;
        *(int *)(state + 0x2dc) = *(int *)(state + 0x2dc) & -2;
        return;
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        if (*(s16 *)(setup + 0x1a) != -1) {
            if (GameBit_Get(*(s16 *)(setup + 0x1a)) == 0) {
                return;
            }
            if ((((EnemyState *)state)->controlFlags & 0x800) != 0) {
                return;
            }
            if ((((EnemyState *)state)->controlFlags & 0x1000) == 0) {
                return;
            }
            player = Obj_GetPlayerObject();
            if (*(s16 *)(setup + 0x18) != -1) {
                if (GameBit_Get(*(s16 *)(setup + 0x18)) != 0) {
                    return;
                }
            }
            if (player != NULL) {
                if (vec3f_distanceSquared((f32 *)(player + 0x18), (f32 *)(setup + 8)) > lbl_803E2600) {
                    enemy_init(obj, setup, 0);
                    ((EnemyState *)state)->controlFlags |= 0x1000;
                    ((EnemyState *)state)->initialFlags = ((EnemyState *)state)->initialFlags & -4097;
                } else {
                    return;
                }
            } else {
                return;
            }
        } else if (*(s16 *)(setup + 0x18) != -1) {
            if (GameBit_Get(*(s16 *)(setup + 0x18)) != 0) {
                return;
            }
            if ((((EnemyState *)state)->controlFlags & 0x800) != 0) {
                return;
            }
            player = Obj_GetPlayerObject();
            if (player != NULL) {
                if (vec3f_distanceSquared((f32 *)(player + 0x18), (f32 *)(setup + 8)) > lbl_803E2600) {
                    enemy_init(obj, setup, 0);
                    ((EnemyState *)state)->controlFlags |= 0x1000;
                    *(u32 *)(state + 0x2e0) &= 0xFFFFEFFF;
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            if (*(u32 *)&((ObjPlacement *)setup)->mapId == 0xFFFFFFFF) {
                return;
            }
            if (*(s16 *)(setup + 0x2c) == 0) {
                return;
            }
            if ((*gMapEventInterface)->isTimedEventActive(((ObjPlacement *)setup)->mapId) != 0) {
                if ((((EnemyState *)state)->controlFlags & 0x800) == 0) {
                    player = Obj_GetPlayerObject();
                    if (player != NULL) {
                        if (vec3f_distanceSquared((f32 *)(player + 0x18), (f32 *)(setup + 8)) > lbl_803E2600) {
                            enemy_init(obj, setup, 0);
                            ((EnemyState *)state)->controlFlags |= 0x1000;
                            *(u32 *)(state + 0x2e0) &= 0xFFFFEFFF;
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }
    if ((((EnemyState *)state)->controlFlags & 0x8000) != 0) {
        hudFn_8011f38c(0);
        (*gPathControlInterface)->attachObject((void *)obj, state + 4);
        ((EnemyState *)state)->controlFlags &= ~0x8003;
        if ((((EnemyState *)state)->flags2E4 & 0x20000) != 0) {
            s2 = *(u8 **)&((GameObject *)obj)->anim.placementData;
            ((GameObject *)obj)->anim.localPosX = *(f32 *)(s2 + 8);
            ((GameObject *)obj)->anim.localPosY = *(f32 *)(s2 + 0xc);
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)(s2 + 0x10);
            ((GameObject *)obj)->anim.rotZ = 0;
            ((GameObject *)obj)->anim.rotY = 0;
            *(s16 *)obj = *(s8 *)(s2 + 0x2a) << 8;
            fz = lbl_803E2574;
            ((GameObject *)obj)->anim.velocityX = fz;
            ((GameObject *)obj)->anim.velocityY = fz;
            ((GameObject *)obj)->anim.velocityZ = fz;
        }
    }
    if ((((EnemyState *)state)->flags2E4 & 0x80000) != 0) {
        if (tricky != NULL && GameBit_Get(0x9e) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        }
        if (tricky != NULL && (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
            (**(void (**)(u8 *, int, int, int))(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    baddie_updateWhileFrozen(obj, state, 0);
    if ((((EnemyState *)state)->controlFlags & 0x1800) == 0) {
        fn_8014BC98(obj, state);
        fn_8014B878(obj, state);
    }
    objAnimFn_8014a9f0(obj, state);
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80151954(int obj, u8 *state);
extern void fn_801522E0(int obj, u8 *state);
extern void fn_80152A94(int obj, u8 *state);
extern void fn_80152EC0(int obj, u8 *state);
extern void fn_801534D8(int obj, u8 *state);
extern void fn_80153C90(int obj, u8 *state);
extern void fn_801542AC(int obj, u8 *state);
extern void mutatedEbaInit(int obj, u8 *state);
extern void mediumbasket_initWhirlpoolState(int obj, u8 *state);
extern void smallbasket_initVariantState(int obj, u8 *state);
extern void smallbasket_initScaledVariantState(int obj, u8 *state);
extern void fn_8014FF58(int obj, u8 *state);
extern void smallbasket_initModelVariantState(int obj, u8 *state);
extern void smallbasket_initTailModelState(int obj, u8 *state);
extern void enemy_animEventCallback();
extern void *memset(void *p, int c, int n);
extern f32 lbl_803DBC58;
extern f32 lbl_803DBC60;
extern f32 lbl_803DBC64;
extern f32 lbl_803DBC68;
extern u8 lbl_8031DBD8[];
extern u8 lbl_8031DBE4[];
extern f32 lbl_803E257C;
extern f32 lbl_803E25B0;

#pragma scheduling off
#pragma peephole off
void enemy_init(int obj, u8 *setup, int flag)
{
    u8 *state = ((GameObject *)obj)->extra;
    f32 fz;

    ((GameObject *)obj)->unkF4 = 0;
    if (flag == 0) {
        if (*(s16 *)(setup + 0x1a) != -1) {
            if (*(s16 *)(setup + 0x18) != -1) {
                if (GameBit_Get(*(s16 *)(setup + 0x18)) == 0) {
                    ((GameObject *)obj)->unkF4 = GameBit_Get(*(s16 *)(setup + 0x1a)) == 0;
                }
            } else {
                ((GameObject *)obj)->unkF4 = GameBit_Get(*(s16 *)(setup + 0x1a)) == 0;
            }
        }
        if (*(u32 *)&((ObjPlacement *)setup)->mapId != 0xFFFFFFFF) {
            if (((GameObject *)obj)->unkF4 == 0) {
                if (*(s16 *)(setup + 0x18) != -1) {
                    ((GameObject *)obj)->unkF4 = GameBit_Get(*(s16 *)(setup + 0x18));
                }
                if (((GameObject *)obj)->unkF4 == 0) {
                    if (*(s16 *)(setup + 0x2c) != 0) {
                        if ((*gMapEventInterface)->isTimedEventActive(((ObjPlacement *)setup)->mapId) == 0) {
                            ((GameObject *)obj)->unkF4 = 1;
                        }
                    }
                }
            }
        }
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ((GameObject *)obj)->anim.alpha = 0;
    } else {
        ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject *)obj)->anim.alpha = 255;
    }
    ((EnemyState *)state)->unk2FC = (f32)setup[0x2f] / lbl_803E257C;
    ((EnemyState *)state)->unk2A8 = (f32)(u32)(setup[0x29] << 3);
    *(int *)(state + 0x2dc) = 0;
    ((EnemyState *)state)->initialFlags = *(int *)(state + 0x2dc);
    *(s16 *)obj = *(s8 *)(setup + 0x2a) << 8;
    ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)setup)->posX;
    ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
    ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)setup)->posZ;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    if (flag == 0) {
        *(int *)(state + 0x2e4) = 0;
        ((EnemyState *)state)->unk2E8 = 0;
        state[0x2f1] = 0;
        state[0x2f2] = 0;
        ((EnemyState *)state)->unk2EC = 0;
        state[0x2f5] = 0;
        fz = lbl_803E2574;
        ((EnemyState *)state)->unk300 = fz;
        ((EnemyState *)state)->unk304 = fz;
        ((EnemyState *)state)->unk308 = fz;
        ((EnemyState *)state)->unk30C = fz;
        state[0x323] = 0;
        ((EnemyState *)state)->unk310 = fz;
        ((EnemyState *)state)->unk2F8 = 0;
        state[0x33a] = 0;
        state[0x33b] = 0;
        ((EnemyState *)state)->unk338 = 0;
        state[0x33c] = 0;
        state[0x33d] = 0;
        ((EnemyState *)state)->unk324 = fz;
        ((EnemyState *)state)->unk328 = fz;
        ((EnemyState *)state)->unk32C = fz;
        ((EnemyState *)state)->unk330 = fz;
        ((EnemyState *)state)->unk334 = fz;
        ((EnemyState *)state)->unk2B4 = -1;
        ((EnemyState *)state)->unk2B6 = ((EnemyState *)state)->unk2B4;
        ((GameObject *)obj)->objectFlags |= *(s8 *)(setup + 0x28) & 7;
        ((EnemyState *)state)->unk2B0 = setup[0x32];
        ((GameObject *)obj)->animEventCallback = (void *)enemy_animEventCallback;
        switch (((GameObject *)obj)->anim.seqId) {
        case 17:
        case 314:
        case 1463:
        case 1464:
        case 1465:
        case 1505:
        case 1958:
            fn_80151954(obj, state);
            break;
        case 216:
        case 641:
            fn_801522E0(obj, state);
            break;
        case 1555:
            fn_80152A94(obj, state);
            break;
        case 1602:
            fn_80152EC0(obj, state);
            break;
        case 1022:
        case 1990:
            fn_801534D8(obj, state);
            break;
        case 1419:
            fn_80153C90(obj, state);
            break;
        case 873:
            fn_801542AC(obj, state);
            break;
        case 593:
            fn_80154C24(obj, state);
            break;
        case 605:
            rachnopInit(obj, (int)state);
            break;
        case 1111:
            baddieInit_80156188(obj, (int)state);
            break;
        case 1239:
            wbInit(obj, (int)state);
            break;
        case 1112:
            mutatedEbaInit(obj, state);
            break;
        case 2129:
            mediumbasket_initWhirlpoolState(obj, state);
            break;
        case 2114:
        case 2123:
            smallbasket_initVariantState(obj, state);
            break;
        case 1196:
            smallbasket_initScaledVariantState(obj, state);
            break;
        case 1063:
            fn_8014FF58(obj, state);
            break;
        case 1698:
        case 1699:
        case 1700:
        case 1701:
            smallbasket_initModelVariantState(obj, state);
            break;
        case 1992:
            smallbasket_initTailModelState(obj, state);
            break;
        default:
            fn_8014FF58(obj, state);
            break;
        }
        ((EnemyState *)state)->unk2B2 = *(u16 *)(state + 0x2b0);
        if (*(u16 *)(setup + 0x34) != 0) {
            *(int *)(state + 0x2e4) = *(int *)(state + 0x2e4) & -39;
        }
        ObjGroup_AddObject(obj, 3);
        state[0x2f0] = 7;
        state[0x2ef] = 2;
        if (*(void **)state == NULL) {
            *(int *)state = (int)mmAlloc(264, 26, 0);
        }
        if (*(void **)state != NULL) {
            memset(*(void **)state, 0, 264);
        }
        if ((*gRomCurveInterface)->initCurve(*(void **)state, (void *)obj, ((EnemyState *)state)->unk2AC,
                                             (int *)&lbl_803DBC58, -1) == 0) {
            ((EnemyState *)state)->controlFlags |= 0x2000;
        }
        (*gPathControlInterface)->init(state + 4, 0, 422, 1);
        if ((((EnemyState *)state)->flags2E4 & 8) != 0) {
            (*gPathControlInterface)->setLocalPointCollision(state + 4, 1, lbl_8031DBE4,
                                                             &lbl_803DBC64, 4);
        }
        if ((((EnemyState *)state)->flags2E4 & 4) != 0) {
            (*gPathControlInterface)->setup(state + 4, 1, lbl_8031DBD8, &lbl_803DBC60, &lbl_803DBC68);
        }
        (*gPathControlInterface)->attachObject((void *)obj, state + 4);
        if ((((EnemyState *)state)->flags2E4 & 0xc) != 0) {
            state[0x25f] = 1;
        }
        if ((((EnemyState *)state)->flags2E4 & 0x8000022) != 0 || *(u16 *)(setup + 0x34) != 0
            || ((GameObject *)obj)->anim.seqId == 1022 || ((GameObject *)obj)->anim.seqId == 1990) {
            *(u32 *)(state + 4) |= 0x40000;
        } else {
            *(u32 *)(state + 4) &= ~0x40000;
        }
        if ((((EnemyState *)state)->flags2E4 & 4) == 0 && (((EnemyState *)state)->flags2E4 & 8) != 0) {
            *(u32 *)(state + 4) &= ~0x3800;
        }
        if (((GameObject *)obj)->unkF4 != 0) {
            ((EnemyState *)state)->controlFlags |= 0x1000;
            ((EnemyState *)state)->initialFlags = ((EnemyState *)state)->initialFlags & -4097;
            ObjHits_DisableObject(obj);
        } else if ((((EnemyState *)state)->flags2E4 & 1) != 0) {
            ObjHits_EnableObject(obj);
        }
    }
    ((EnemyState *)state)->unk2D8 = lbl_803E2574;
    if (lbl_803E25B0 < ((EnemyState *)state)->unk2A8) {
        ((EnemyState *)state)->unk2A8 = lbl_803E25B0;
    }
    if (lbl_803E25B0 < ((EnemyState *)state)->unk2AC) {
        ((EnemyState *)state)->unk2AC = lbl_803E25B0;
    }
}
#pragma peephole reset
#pragma scheduling reset
