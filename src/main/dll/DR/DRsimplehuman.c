#include "ghidra_import.h"
#include "main/dll/DR/DRsimplehuman.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_800069a8();
extern double FUN_80017708();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017958();
extern int FUN_80017a54();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjGroup_AddObject();
extern int FUN_800620e8();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801e8278();
extern undefined4 FUN_801e85b0();
extern undefined4 FUN_801f4f98();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd18;
extern undefined4 DAT_803dcd1c;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803e6708;
extern undefined4 DAT_803e670a;
extern f64 DOUBLE_803e6730;
extern f32 lbl_803DC074;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;
extern f32 lbl_803E6718;
extern f32 lbl_803E671C;
extern f32 lbl_803E6720;
extern f32 lbl_803E672C;
extern f32 lbl_803E6738;
extern f32 lbl_803E673C;
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;
extern f32 lbl_803E6748;
extern f32 lbl_803E674C;
extern f32 lbl_803E6750;
extern f32 lbl_803E6754;

/*
 * --INFO--
 *
 * Function: spdrape_update
 * EN v1.0 Address: 0x801E9344
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E93B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *Obj_GetPlayerObject(void);
extern f32 getXZDistance(f32 *a, f32 *b);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern u32 randomGetRange(int min, int max);
extern void ObjAnim_SetCurrentMove(int obj, int animId, f32 speed, int flag);
extern u8 ObjAnim_AdvanceCurrentMove(int obj, f32 cur, f32 dt, int flag);
extern void Camera_GetCurrentViewSlot(void);
extern f32 lbl_803DC0B0;
extern f32 lbl_803DC0B4;
extern byte framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5AA0;
extern f32 lbl_803E5AA4;
extern f32 lbl_803E5AA8;
extern f32 lbl_803E5AAC;
extern f32 lbl_803E5AB0;
extern f32 lbl_803E5AB4;
extern f32 lbl_803E5AB8;
extern f32 lbl_803E5ABC;

#pragma scheduling off
#pragma peephole off
void spdrape_update(int obj)
{
    f32 *state;
    char *player;

    state = *(f32 **)(obj + 0xb8);
    player = (char *)Obj_GetPlayerObject();
    switch (*(s16 *)(obj + 0xa0)) {
    case 0:
        if ((s16)(*(s16 *)((char *)state + 0x14) -= framesThisStep) <= 0) {
            Sfx_PlayFromObject(obj, 0x13f);
            *(s16 *)((char *)state + 0x14) = randomGetRange(0xb4, 300);
        }
        if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < lbl_803E5AA4) {
            if (player != 0) {
                if (state[3] + (state[1] * *(f32 *)(player + 0xc) + state[2] * *(f32 *)(player + 0x14)) < lbl_803E5AA0) {
                    *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B0;
                }
                else {
                    *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8 **)((char *)state + 0x10), lbl_803E5AA0, 0);
            *state = lbl_803E5AA8;
            Sfx_PlayFromObject(obj, 0x140);
            Camera_GetCurrentViewSlot();
        }
        break;
    case 1:
    case 4:
        if (*(u8 *)((char *)state + 0x16) != 0) {
            if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) > lbl_803E5AAC) {
                ObjAnim_SetCurrentMove(obj, (*(u8 **)((char *)state + 0x10))[2], lbl_803E5AA0, 0);
                Sfx_PlayFromObject(obj, 0x140);
                *state = lbl_803E5AB0;
            }
            else {
                ObjAnim_SetCurrentMove(obj, (*(u8 **)((char *)state + 0x10))[1], lbl_803E5AA0, 0);
                *state = lbl_803E5AB4;
            }
        }
        break;
    case 2:
    case 5:
        Sfx_PlayFromObject(obj, 0x141);
        if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) > lbl_803E5AAC) {
            ObjAnim_SetCurrentMove(obj, (*(u8 **)((char *)state + 0x10))[2], lbl_803E5AA0, 0);
            Sfx_StopObjectChannel(obj, 0x40);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AB0;
        }
        break;
    case 3:
    case 6:
        if ((*(f32 *)(obj + 0x98) > lbl_803E5AB8) && (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < lbl_803E5AA4)) {
            if (player != 0) {
                if (state[3] + (state[1] * *(f32 *)(player + 0xc) + state[2] * *(f32 *)(player + 0x14)) < lbl_803E5AA0) {
                    *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B0;
                }
                else {
                    *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8 **)((char *)state + 0x10), lbl_803E5AA0, 0);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AA8;
        }
        else if (*(u8 *)((char *)state + 0x16) != 0) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5AA0, 0);
            *state = lbl_803E5ABC;
            Camera_GetCurrentViewSlot();
        }
        break;
    }
    *(u8 *)((char *)state + 0x16) = ObjAnim_AdvanceCurrentMove(obj, *state, timeDelta, 0);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801e9348
 * EN v1.0 Address: 0x801E9348
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801E94EC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9348(void)
{
  FUN_800068cc();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e9368
 * EN v1.0 Address: 0x801E9368
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x801E9518
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9368(int *param_1)
{
  int iVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  float local_80;
  float local_7c [2];
  int local_74;
  int aiStack_70 [7];
  float afStack_54 [18];
  
  pfVar3 = (float *)param_1[0x2e];
  iVar2 = param_1[0x13];
  if (*pfVar3 < (float)param_1[4]) {
    param_1[10] = (int)-(lbl_803E670C * lbl_803DC074 - (float)param_1[10]);
  }
  FUN_80017a88((double)(lbl_803DC074 * (float)param_1[9] * pfVar3[1]),
               (double)((float)param_1[10] * lbl_803DC074),
               (double)(lbl_803DC074 * (float)param_1[0xb] * pfVar3[1]),(int)param_1);
  dVar4 = FUN_80293900((double)((float)param_1[9] * (float)param_1[9] +
                               (float)param_1[0xb] * (float)param_1[0xb]));
  FUN_8002f6ac(dVar4,(int)param_1,&local_80);
  FUN_8002fc3c((double)local_80,(double)lbl_803DC074);
  if ((float)param_1[4] < *pfVar3) {
    param_1[4] = (int)*pfVar3;
    param_1[10] = (int)lbl_803E6710;
  }
  iVar1 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x0,aiStack_70,param_1,8,0xffffffff,0xff,
                       10);
  if (iVar1 != 0) {
    FUN_8001777c(afStack_54,(float *)(param_1 + 9),local_7c);
    param_1[9] = (int)local_7c[0];
    param_1[0xb] = local_74;
    iVar1 = FUN_80017730();
    *(short *)param_1 = (short)iVar1;
  }
  iVar1 = FUN_80017a98();
  dVar4 = FUN_80017708((float *)(iVar1 + 0x18),(float *)(param_1 + 6));
  if (dVar4 < (double)lbl_803E6718) {
    FUN_80006824((uint)param_1,*(ushort *)(pfVar3 + 3));
    FUN_80081118((double)lbl_803E671C,param_1,(int)*(short *)((int)pfVar3 + 0xe),0x28);
    *(ushort *)(param_1 + 0x2c) = *(ushort *)(param_1 + 0x2c) | 0x8000;
    *(ushort *)((int)param_1 + 6) = *(ushort *)((int)param_1 + 6) | 0x4000;
    (**(code **)(**(int **)((int)pfVar3[2] + 0x68) + 0x50))
              (pfVar3[2],*(char *)(iVar2 + 0x19) != '\0',*(char *)(iVar2 + 0x19) == '\0');
  }
  if (((*(ushort *)(param_1 + 0x2c) & 0x800) != 0) && ((int)*(short *)(pfVar3 + 4) != 0)) {
    FUN_800810f4((double)lbl_803E671C,(double)lbl_803E6720,param_1,5,
                 (int)*(short *)(pfVar3 + 4) & 0xff,1,0x14,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e9690
 * EN v1.0 Address: 0x801E9690
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x801E9764
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9690(short *param_1,int param_2)
{
  char cVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  undefined2 local_38;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  local_38 = DAT_803e6708;
  local_36 = DAT_803e670a;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293f90();
  *(float *)(param_1 + 0x12) = (float)-dVar5;
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(param_1 + 0x16) = (float)-dVar5;
  *(char *)((int)param_1 + 0xad) = '\x01' - *(char *)(param_2 + 0x19);
  uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_20 = 0x43300000;
  *pfVar4 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6730);
  uStack_14 = randomGetRange(0,100);
  uStack_14 = uStack_14 ^ 0x80000000;
  local_18 = 0x43300000;
  pfVar4[1] = lbl_803E672C +
              (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6730) / lbl_803E6718;
  pfVar4[2] = *(float *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  FUN_800068d0((uint)param_1,0x406);
  iVar2 = FUN_80017a54((int)param_1);
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x01') {
    *(undefined2 *)(pfVar4 + 3) = 0x42;
    *(undefined2 *)((int)pfVar4 + 0xe) = 1;
    *(undefined2 *)(pfVar4 + 4) = 0;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    uVar3 = randomGetRange(0,2);
    *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = *(undefined *)((int)&local_38 + uVar3);
    *(undefined2 *)(pfVar4 + 3) = 0x41;
    *(undefined2 *)((int)pfVar4 + 0xe) = 4;
    *(undefined2 *)(pfVar4 + 4) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e983c
 * EN v1.0 Address: 0x801E983C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E997C
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e983c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: spitembeam_init
 * EN v1.0 Address: 0x801E9900
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void spitembeam_init(int obj)
{
  *(ushort *)(obj + 0xb0) = (ushort)(*(ushort *)(obj + 0xb0) | 0x6000);
}
#pragma peephole reset


/* Trivial 4b 0-arg blr leaves. */
void spdrape_release(void) {}
void spdrape_initialise(void) {}
void spitembeam_free(void) {}
void spitembeam_render(void) {}
void spitembeam_hitDetect(void) {}
void spitembeam_release(void) {}
void spitembeam_initialise(void) {}

extern int* ObjGroup_FindNearestObject(int group, int *obj, f32 *dist);
extern int* objFindTexture(int *obj, int a, int b);
extern f32 lbl_803E5AD8;

#pragma scheduling off
#pragma peephole off
void spitembeam_update(int *obj) {
    int *target;
    u8 *def;
    int *tex;
    f32 d;

    target = *(int**)((char*)obj + 0xf4);
    def = *(u8**)((char*)obj + 0x4c);
    d = lbl_803E5AD8;
    if (target == NULL) {
        *(int**)((char*)obj + 0xf4) = ObjGroup_FindNearestObject(9, obj, &d);
    } else {
        if (((int(*)(int*, s16))(**(int ***)((char*)target + 0x68))[10])(target, *(s16*)(def + 0x1a)) == 0
            || ((int(*)(int*, s16))(**(int ***)((char*)target + 0x68))[11])(target, *(s16*)(def + 0x1a)) != 0) {
            *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
            *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL) {
            *(s16*)((char*)tex + 8) += 8;
            if (*(s16*)((char*)tex + 8) > 0x400) {
                *(s16*)((char*)tex + 8) -= 0x400;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int spitembeam_getExtraSize(void) { return 0x0; }
int spitembeam_getObjectTypeId(void) { return 0x0; }

extern f32 lbl_803E5AA0;
extern f32 lbl_803E5ABC;
extern f32 lbl_803E5AC0;
extern f32 lbl_803E5AC4;
extern f32 lbl_803E5AC8;
extern f32 lbl_803E5ACC;
extern f32 lbl_803DC0B0;
extern f32 lbl_803DC0B4;
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern void *Obj_GetPlayerObject(void);
extern unsigned long randomGetRange(int a, int b);

#pragma scheduling off
#pragma peephole off
void spdrape_init(int *obj, u8 *def) {
    f32 *state;
    int *player;
    state = *(f32 **)((char *)obj + 0xb8);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
    *(u16 *)((char *)obj + 0xb0) |= 0x4000;
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    if (*(s16 *)((char *)def + 0x1a) != 0) {
        *(f32 *)((char *)obj + 8) = (f32)(s32)*(s16 *)((char *)def + 0x1a) / lbl_803E5AC4 * lbl_803E5AC0;
    }
    state[0] = lbl_803E5ABC;
    state[1] = fn_80293E80(lbl_803E5AC8 * (f32)(s32)*(s16 *)obj / lbl_803E5ACC);
    state[2] = sin(lbl_803E5AC8 * (f32)(s32)*(s16 *)obj / lbl_803E5ACC);
    state[3] = -(state[1] * *(f32 *)((char *)obj + 0xc) + state[2] * *(f32 *)((char *)obj + 0x14));
    *(s16 *)((char *)state + 0x14) = (s16)randomGetRange(0xb4, 0x12c);
    player = (int *)Obj_GetPlayerObject();
    if (player != NULL) {
        if (state[1] * *(f32 *)((char *)player + 0xc) + state[2] * *(f32 *)((char *)player + 0x14) + state[3] < lbl_803E5AA0) {
            *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B0;
        } else {
            *(int *)((char *)state + 0x10) = (int)&lbl_803DC0B4;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef union {
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} ShWGPipe;
volatile ShWGPipe GXWGFifo : (0xCC008000);

static inline void shPos3f32(const f32 x, const f32 y, const f32 z) { GXWGFifo.f32 = x; GXWGFifo.f32 = y; GXWGFifo.f32 = z; }
static inline void shColor4u8(const u8 r, const u8 g, const u8 b, const u8 a) { GXWGFifo.u8 = r; GXWGFifo.u8 = g; GXWGFifo.u8 = b; GXWGFifo.u8 = a; }
static inline void shTexCoord2f32(const f32 s, const f32 t) { GXWGFifo.f32 = s; GXWGFifo.f32 = t; }

typedef struct {
    u8 r, g, b, a;
} ShColor;

extern void selectTexture(int tex, int p);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void GXSetTevColor(int reg, ShColor color);
extern void gxSetZMode_(int a, int b, int c);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void gxSetPeControl_ZCompLoc_(int a);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern f32 *Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(f32 *m, int id);
extern void GXSetCurrentMtx(int id);
extern void getAmbientColor(int mode, u8 *r, u8 *g, u8 *b);
extern void GXBegin(int prim, int fmt, int n);
extern int lbl_803DDC60;
extern ShColor lbl_803E5AE4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

/*
 * --INFO--
 *
 * Function: fn_801E991C
 * EN v1.0 Address: 0x801E991C
 * EN v1.0 Size: 740b
 */
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void fn_801E991C(int p1, char *table)
{
    u8 r;
    u8 g;
    u8 b;
    ShColor color;
    char *p;
    int i;

    color = lbl_803E5AE4;
    selectTexture(lbl_803DDC60, 0);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    textRenderSetupFn_80079804();
    GXSetTevColor(2, color);
    gxSetZMode_(1, 3, 0);
    GXSetBlendMode(1, 4, 5, 5);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    getAmbientColor(0, &r, &g, &b);
    p = table;
    for (i = 0; i < 9; i++) {
        if (((*(u8 *)(p + 0x4ce) & 1) != 0) && (*(s16 *)(p + 0x4cc) >= 4)) {
            int j;
            f32 *verts;
            f32 u1, u0;
            verts = *(f32 **)(p + 0x4c8);
            u0 = lbl_803E5AE8;
            u1 = lbl_803E5AEC;
            for (j = 0; j < *(s16 *)(p + 0x4cc) - 2; j += 2) {
                GXBegin(0x80, 2, 4);
                shPos3f32(verts[0] - playerMapOffsetX, verts[0+1], verts[0+2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8)*(s16 *)((char *)verts + 0xc));
                shTexCoord2f32(u0, u0);
                GXWGFifo.f32 = u0;
                shPos3f32(verts[4] - playerMapOffsetX, verts[4+1], verts[4+2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8)*(s16 *)((char *)verts + 0x1c));
                shTexCoord2f32(u1, u0);
                shPos3f32(verts[0xc] - playerMapOffsetX, verts[0xc+1], verts[0xc+2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8)*(s16 *)((char *)verts + 0x3c));
                shTexCoord2f32(u1, u0);
                shPos3f32(verts[8] - playerMapOffsetX, verts[8+1], verts[8+2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8)*(s16 *)((char *)verts + 0x2c));
                shTexCoord2f32(u0, u0);
                GXWGFifo.f32 = u0;
                verts += 8;
            }
        }
        p += 8;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma opt_common_subs reset
