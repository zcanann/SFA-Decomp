#include "ghidra_import.h"
#include "main/dll/projswitch.h"

#define SFXmv_liftloop 158

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
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
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
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
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
  if (*(short *)(param_1 + 0x46) == 0x7c8) {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)(param_1 + 0xb8) + 0x36c),FUN_80159bd0);
  }
  else {
    FUN_8001789c(param_2,*param_2,*(int **)(*(int *)(param_1 + 0xb8) + 0x36c),(undefined *)0x0);
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
  (**(code **)(*DAT_803dd6f8 + 0x14))(iVar3);
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
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((visible != 0) && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
    uVar1 = *(uint *)(iVar3 + 0x2e8);
    if ((uVar1 & 3) != 0) {
      if ((uVar1 & 1) != 0) {
        *(uint *)(iVar3 + 0x2e8) = uVar1 & ~1;
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 2;
      }
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8008111c((double)lbl_803E3200,(double)*(float *)(iVar3 + 0x30c),param_1,3,
                   *(int **)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 4) != 0) {
      if (*(int *)(iVar3 + 0x368) == 0) {
        piVar2 = FUN_80017624(0,'\x01');
        *(int **)(iVar3 + 0x368) = piVar2;
      }
      FUN_8008111c((double)lbl_803E3200,(double)*(float *)(iVar3 + 0x30c),param_1,4,
                   *(int **)(iVar3 + 0x368));
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
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(iVar2 + 0x368) != 0) && (iVar1 = FUN_800175c4(*(int *)(iVar2 + 0x368)), iVar1 == 0))
  {
    FUN_80017620(*(uint *)(iVar2 + 0x368));
    *(undefined4 *)(iVar2 + 0x368) = 0;
  }
  *(undefined4 *)(iVar2 + 0x340) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50);
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (((*(int *)(param_1 + 200) != 0) &&
      (iVar1 = *(int *)(*(int *)(param_1 + 200) + 0x54), iVar1 != 0)) &&
     (*(int *)(iVar1 + 0x50) != 0)) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (*(int *)(iVar2 + 0x36c) != 0) {
    FUN_800178ac(*(int *)(iVar2 + 0x36c));
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
extern u32 lbl_803DDA50;
extern void Resource_Release(u32);
#pragma scheduling off
#pragma peephole off
void enemy_release(void) { if (lbl_803DDA50 != 0) { Resource_Release(lbl_803DDA50); lbl_803DDA50 = 0; } }
void enemy_initialise(void) { if (lbl_803DDA50 == 0) lbl_803DDA50 = Resource_Acquire(0x5a, 1); }
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
    int *state = *(int **)((char *)obj + 0xb8);
    if (visible != 0) {
        if (*(int *)((char *)obj + 0xf4) == 0) {
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

extern int fn_8001DB64(int light);
extern void ModelLightStruct_free(int light);
extern void fn_80026C54(int p);

#pragma scheduling off
#pragma peephole off
void enemy_hitDetect(int obj)
{
    u8 *state = *(u8 **)(obj + 0xb8);

    if (*(void **)(state + 0x368) != NULL && fn_8001DB64(*(int *)(state + 0x368)) == 0) {
        ModelLightStruct_free(*(int *)(state + 0x368));
        *(int *)(state + 0x368) = 0;
    }
    *(int *)(state + 0x340) = *(int *)(*(int *)(obj + 0x54) + 0x50);
    if (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL) {
        *(u8 *)(*(int *)(obj + 0x54) + 0x70) = 1;
    }
    if (*(void **)(obj + 0xc8) != NULL && *(void **)(*(int *)(obj + 0xc8) + 0x54) != NULL
        && *(void **)(*(int *)(*(int *)(obj + 0xc8) + 0x54) + 0x50) != NULL) {
        *(u8 *)(*(int *)(obj + 0x54) + 0x70) = 1;
    }
    if (*(void **)(state + 0x36c) != NULL) {
        fn_80026C54(*(int *)(state + 0x36c));
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80026C88(int p);
extern int *gExpgfxInterface;
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
    u8 n;

    state = *(u8 **)(obj + 0xb8);

    if (*(void **)(state + 0x36c) != NULL) {
        fn_80026C88(*(int *)(state + 0x36c));
    }
    if (*(void **)(state + 0x368) != NULL) {
        ModelLightStruct_free(*(int *)(state + 0x368));
        *(int *)(state + 0x368) = 0;
    }
    if (*(void **)state != NULL) {
        mm_free(*(int *)state);
        *(int *)state = 0;
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0x7c8:
        smallbasket_stopLoopSfx(obj, state);
        break;
    case 0x851:
        if ((int)ObjGroup_ContainsObject(obj, 0x50) != 0) {
            ObjGroup_RemoveObject(obj, 0x50);
        }
        break;
    }
    n = *(u8 *)(obj + 0xeb);
    for (i = 0; i < n; i++) {
        child = *(u8 **)(obj + 0xc8);
        if (child != NULL) {
            ObjLink_DetachChild(obj, child);
            if (flag == 0 || (*(u16 *)(child + 0xb0) & 0x10) == 0) {
                Obj_FreeObject((int)child);
            }
        }
    }
    (**(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
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
extern int *gObjectTriggerInterface;
extern int *gMapEventInterface;
extern int *gPathControlInterface;
extern f32 lbl_803E2574;
extern f32 lbl_803E2600;

void enemy_init(int obj, u8 *setup, int flag);

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

    state = *(u8 **)(obj + 0xb8);
    setup = *(u8 **)(obj + 0x4c);
    tricky = getTrickyObject();
    if (getCurUiDll() == 4) {
        return;
    }
    if ((*(u32 *)(state + 0x2e4) & 0x8000006) != 0) {
        if (objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14)) == -1) {
            return;
        }
    } else {
        if (isInBounds(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14)) == 0) {
            return;
        }
    }
    if (objIsFrozen(obj) != 0) {
        baddie_updateWhileFrozen(obj, state, 1);
        return;
    }
    if (*(void **)(state + 0x29c) == NULL) {
        *(u8 **)(state + 0x29c) = Obj_GetPlayerObject();
    } else if ((*(u16 *)(*(int *)(state + 0x29c) + 0xb0) & 0x40) != 0) {
        *(u8 **)(state + 0x29c) = Obj_GetPlayerObject();
    }
    *(int *)(state + 0x2e0) = *(int *)(state + 0x2dc);
    baddieInstantiateWeapon(obj, state);
    flags = *(u32 *)(state + 0x2dc);
    if ((flags & 1) != 0 && (flags & 2) == 0) {
        if (*(s8 *)(setup + 0x2e) == -1) {
            return;
        }
        if (setup != NULL && (setup[0x2b] & 8) != 0) {
            *(f32 *)(obj + 0xc) = *(f32 *)(setup + 8);
            *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
        }
        (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(*(s8 *)(setup + 0x2e), obj, -1);
        *(u32 *)(state + 0x2dc) |= 2;
        *(int *)(state + 0x2dc) = *(int *)(state + 0x2dc) & -2;
        return;
    }
    if (*(int *)(obj + 0xf4) != 0) {
        if (*(s16 *)(setup + 0x1a) != -1) {
            if (GameBit_Get(*(s16 *)(setup + 0x1a)) == 0) {
                return;
            }
            if ((*(u32 *)(state + 0x2dc) & 0x800) != 0) {
                return;
            }
            if ((*(u32 *)(state + 0x2dc) & 0x1000) == 0) {
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
                    *(u32 *)(state + 0x2dc) |= 0x1000;
                    *(int *)(state + 0x2e0) = *(int *)(state + 0x2e0) & -4097;
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
            if ((*(u32 *)(state + 0x2dc) & 0x800) != 0) {
                return;
            }
            player = Obj_GetPlayerObject();
            if (player != NULL) {
                if (vec3f_distanceSquared((f32 *)(player + 0x18), (f32 *)(setup + 8)) > lbl_803E2600) {
                    enemy_init(obj, setup, 0);
                    *(u32 *)(state + 0x2dc) |= 0x1000;
                    *(u32 *)(state + 0x2e0) &= 0xFFFFEFFF;
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            if (*(u32 *)(setup + 0x14) == 0xFFFFFFFF) {
                return;
            }
            if (*(s16 *)(setup + 0x2c) == 0) {
                return;
            }
            if ((**(int (**)(int))(*gMapEventInterface + 0x68))(*(int *)(setup + 0x14)) != 0) {
                if ((*(u32 *)(state + 0x2dc) & 0x800) == 0) {
                    player = Obj_GetPlayerObject();
                    if (player != NULL) {
                        if (vec3f_distanceSquared((f32 *)(player + 0x18), (f32 *)(setup + 8)) > lbl_803E2600) {
                            enemy_init(obj, setup, 0);
                            *(u32 *)(state + 0x2dc) |= 0x1000;
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
    if ((*(u32 *)(state + 0x2dc) & 0x8000) != 0) {
        hudFn_8011f38c(0);
        (**(void (**)(int, u8 *))(*gPathControlInterface + 0x20))(obj, state + 4);
        *(u32 *)(state + 0x2dc) &= ~0x8003;
        if ((*(u32 *)(state + 0x2e4) & 0x20000) != 0) {
            s2 = *(u8 **)(obj + 0x4c);
            *(f32 *)(obj + 0xc) = *(f32 *)(s2 + 8);
            *(f32 *)(obj + 0x10) = *(f32 *)(s2 + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(s2 + 0x10);
            *(s16 *)(obj + 4) = 0;
            *(s16 *)(obj + 2) = 0;
            *(s16 *)obj = *(s8 *)(s2 + 0x2a) << 8;
            fz = lbl_803E2574;
            *(f32 *)(obj + 0x24) = fz;
            *(f32 *)(obj + 0x28) = fz;
            *(f32 *)(obj + 0x2c) = fz;
        }
    }
    if ((*(u32 *)(state + 0x2e4) & 0x80000) != 0) {
        if (tricky != NULL && GameBit_Get(0x9e) != 0) {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        } else {
            *(u8 *)(obj + 0xaf) |= 0x10;
        }
        if (tricky != NULL && (*(u8 *)(obj + 0xaf) & 4) != 0) {
            (**(void (**)(u8 *, int, int, int))(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    baddie_updateWhileFrozen(obj, state, 0);
    if ((*(u32 *)(state + 0x2dc) & 0x1800) == 0) {
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
extern void fn_8014BE1C();
extern void *memset(void *p, int c, int n);
extern int *gRomCurveInterface;
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
    u8 *state = *(u8 **)(obj + 0xb8);

    *(int *)(obj + 0xf4) = 0;
    if (flag == 0) {
        if (*(s16 *)(setup + 0x1a) != -1) {
            if (*(s16 *)(setup + 0x18) != -1) {
                if (GameBit_Get(*(s16 *)(setup + 0x18)) == 0) {
                    *(int *)(obj + 0xf4) = GameBit_Get(*(s16 *)(setup + 0x1a)) == 0;
                }
            } else {
                *(int *)(obj + 0xf4) = GameBit_Get(*(s16 *)(setup + 0x1a)) == 0;
            }
        }
        if (*(u32 *)(setup + 0x14) != 0xFFFFFFFF) {
            if (*(int *)(obj + 0xf4) == 0) {
                if (*(s16 *)(setup + 0x18) != -1) {
                    *(int *)(obj + 0xf4) = GameBit_Get(*(s16 *)(setup + 0x18));
                }
                if (*(int *)(obj + 0xf4) == 0) {
                    if (*(s16 *)(setup + 0x2c) != 0) {
                        if ((**(int (**)(int))(*gMapEventInterface + 0x68))(*(int *)(setup + 0x14)) == 0) {
                            *(int *)(obj + 0xf4) = 1;
                        }
                    }
                }
            }
        }
    }
    if (*(int *)(obj + 0xf4) != 0) {
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    } else {
        *(s16 *)(obj + 6) &= ~0x4000;
        *(u8 *)(obj + 0x36) = 255;
    }
    *(f32 *)(state + 0x2fc) = (f32)setup[0x2f] / lbl_803E257C;
    *(f32 *)(state + 0x2a8) = (f32)(setup[0x29] << 3);
    *(int *)(state + 0x2dc) = 0;
    *(int *)(state + 0x2e0) = *(int *)(state + 0x2dc);
    *(s16 *)obj = *(s8 *)(setup + 0x2a) << 8;
    *(f32 *)(obj + 0xc) = *(f32 *)(setup + 8);
    *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
    *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
    *(u8 *)(obj + 0xaf) &= ~8;
    if (flag == 0) {
        *(int *)(state + 0x2e4) = 0;
        *(int *)(state + 0x2e8) = 0;
        state[0x2f1] = 0;
        state[0x2f2] = 0;
        *(s16 *)(state + 0x2ec) = 0;
        state[0x2f5] = 0;
        *(f32 *)(state + 0x300) = lbl_803E2574;
        *(f32 *)(state + 0x304) = lbl_803E2574;
        *(f32 *)(state + 0x308) = lbl_803E2574;
        *(f32 *)(state + 0x30c) = lbl_803E2574;
        state[0x323] = 0;
        *(f32 *)(state + 0x310) = lbl_803E2574;
        *(s16 *)(state + 0x2f8) = 0;
        state[0x33a] = 0;
        state[0x33b] = 0;
        *(s16 *)(state + 0x338) = 0;
        state[0x33c] = 0;
        state[0x33d] = 0;
        *(f32 *)(state + 0x324) = lbl_803E2574;
        *(f32 *)(state + 0x328) = lbl_803E2574;
        *(f32 *)(state + 0x32c) = lbl_803E2574;
        *(f32 *)(state + 0x330) = lbl_803E2574;
        *(f32 *)(state + 0x334) = lbl_803E2574;
        *(s16 *)(state + 0x2b4) = -1;
        *(s16 *)(state + 0x2b6) = *(s16 *)(state + 0x2b4);
        *(u16 *)(obj + 0xb0) |= *(s8 *)(setup + 0x28) & 7;
        *(s16 *)(state + 0x2b0) = setup[0x32];
        *(int *)(obj + 0xbc) = (int)fn_8014BE1C;
        switch (*(s16 *)(obj + 0x46)) {
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
        *(s16 *)(state + 0x2b2) = *(u16 *)(state + 0x2b0);
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
        if ((u8)(**(int (**)(int, int, f32, f32 *, int))(*gRomCurveInterface + 0x8c))(*(int *)state, obj, *(f32 *)(state + 0x2ac), &lbl_803DBC58, -1) == 0) {
            *(u32 *)(state + 0x2dc) |= 0x2000;
        }
        (**(void (**)(u8 *, int, int, int))(*gPathControlInterface + 0x4))(state + 4, 0, 422, 1);
        if ((*(u32 *)(state + 0x2e4) & 8) != 0) {
            (**(void (**)(u8 *, int, u8 *, f32 *, int))(*gPathControlInterface + 0x8))(state + 4, 1, lbl_8031DBE4, &lbl_803DBC64, 4);
        }
        if ((*(u32 *)(state + 0x2e4) & 4) != 0) {
            (**(void (**)(u8 *, int, u8 *, f32 *, f32 *))(*gPathControlInterface + 0xc))(state + 4, 1, lbl_8031DBD8, &lbl_803DBC60, &lbl_803DBC68);
        }
        (**(void (**)(int, u8 *))(*gPathControlInterface + 0x20))(obj, state + 4);
        if ((*(u32 *)(state + 0x2e4) & 0xc) != 0) {
            state[0x25f] = 1;
        }
        if ((*(u32 *)(state + 0x2e4) & 0x8000022) != 0 || *(u16 *)(setup + 0x34) != 0
            || *(s16 *)(obj + 0x46) == 1022 || *(s16 *)(obj + 0x46) == 1990) {
            *(u32 *)(state + 4) |= 0x40000;
        } else {
            *(u32 *)(state + 4) &= ~0x40000;
        }
        if ((*(u32 *)(state + 0x2e4) & 4) == 0 && (*(u32 *)(state + 0x2e4) & 8) != 0) {
            *(u32 *)(state + 4) &= ~0x3800;
        }
        if (*(int *)(obj + 0xf4) != 0) {
            *(u32 *)(state + 0x2dc) |= 0x1000;
            *(int *)(state + 0x2e0) = *(int *)(state + 0x2e0) & -4097;
            ObjHits_DisableObject(obj);
        } else if ((*(u32 *)(state + 0x2e4) & 1) != 0) {
            ObjHits_EnableObject(obj);
        }
    }
    *(f32 *)(state + 0x2d8) = lbl_803E2574;
    if (*(f32 *)(state + 0x2a8) > lbl_803E25B0) {
        *(f32 *)(state + 0x2a8) = lbl_803E25B0;
    }
    if (*(f32 *)(state + 0x2ac) > lbl_803E25B0) {
        *(f32 *)(state + 0x2ac) = lbl_803E25B0;
    }
}
#pragma peephole reset
#pragma scheduling reset
