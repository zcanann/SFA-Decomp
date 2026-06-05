#include "ghidra_import.h"
#include "main/dll/NW/NWmammoth.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_80017688();
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017a28();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern void ObjHits_EnableObject(int obj);
extern void ObjHits_RefreshObjectState(int obj);
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern u32 randomGetRange(int min,int max);
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined4 FUN_80081118();
extern undefined4 edibleMushroomFn_801d083c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4* DAT_803dd71c;
extern int *gExpgfxInterface;
extern f64 DOUBLE_803e5f58;
extern f32 FLOAT_803e5f20;
extern f32 FLOAT_803e5f2c;
extern f32 FLOAT_803e5f38;
extern f32 FLOAT_803e5f40;
extern f32 FLOAT_803e5f78;
extern f32 FLOAT_803e5f7c;
extern f32 FLOAT_803e5f80;
extern f32 FLOAT_803e5f84;
extern f32 FLOAT_803e5f88;
extern f32 FLOAT_803e5f8c;

extern void *Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int bit);
extern f32 Vec_distance(int a, int b);
extern void EdibleMushroom_SeqFn(void);

extern void *gRomCurveInterface;

extern f32 lbl_803E5288;
extern f32 lbl_803E52A0;
extern f32 lbl_803E52A8;
extern f64 lbl_803E52C0;
extern f32 lbl_803E52E0;
extern f32 lbl_803E52E4;
extern f32 lbl_803E52E8;
extern f32 lbl_803E52EC;
extern f32 lbl_803E52F0;
extern f32 lbl_803E52F4;
extern f32 lbl_803E52F8;
extern f32 lbl_803E52FC;
extern f32 lbl_803E5300;
extern f32 lbl_803E5304;
extern f64 lbl_803E5308;

/*
 * --INFO--
 *
 * Function: ediblemushroom_init
 * EN v1.0 Address: 0x801D1978
 * EN v1.0 Size: 644b
 */
#pragma scheduling off
#pragma peephole off
void ediblemushroom_init(int obj, int aux)
{
    int state;
    int player;
    int local_x;
    ObjAnimEventList animEvents;
    f32 dist;

    state = *(int *)(obj + 0xb8);
    local_x = 0x19;
    player = (int)Obj_GetPlayerObject();

    *(int *)(obj + 0xbc) = (int)&EdibleMushroom_SeqFn;
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x4000);

    if (GameBit_Get(*(short *)(aux + 0x1a)) != 0) {
        *(u8 *)(state + 0x136) = 8;
        ObjHits_DisableObject(obj);
        *(short *)(obj + 0x6) = (short)(*(short *)(obj + 0x6) | 0x4000);
    }

    *(u32 *)(*(int *)(obj + 0x64) + 0x30) |= 0x810;

    *(f32 *)(state + 0x110) = lbl_803E52E0;
    *(f32 *)(state + 0x114) = lbl_803E52E4 *
        ((f32)*(u8 *)(aux + 0x1c) / lbl_803E52E8);

    ObjAnim_SetCurrentMove(obj, 1, lbl_803E5288, 0);
    ObjAnim_AdvanceCurrentMove(lbl_803E52A8, lbl_803E52A8, obj, &animEvents);
    *(f32 *)(state + 0x118) = animEvents.rootDeltaX;
    if (*(f32 *)(state + 0x118) < lbl_803E5288) {
        *(f32 *)(state + 0x118) = -*(f32 *)(state + 0x118);
    }
    *(f32 *)(state + 0x118) = *(f32 *)(state + 0x118) * *(f32 *)(state + 0x110);
    *(f32 *)(state + 0x118) = *(f32 *)(state + 0x118) + lbl_803E52A0;

    ObjAnim_SetCurrentMove(obj, 4, lbl_803E5288, 0);
    ObjAnim_AdvanceCurrentMove(lbl_803E52A8, lbl_803E52A8, obj, &animEvents);
    *(f32 *)(state + 0x11c) = animEvents.rootDeltaZ;
    if (*(f32 *)(state + 0x11c) < lbl_803E5288) {
        *(f32 *)(state + 0x11c) = -*(f32 *)(state + 0x11c);
    }
    *(f32 *)(state + 0x11c) = *(f32 *)(state + 0x11c) + lbl_803E52A0;

    ObjMsg_AllocQueue(obj, 1);

    {
        int v = *(u8 *)(aux + 0x18);
        if (v < 6) {
            if (v >= 4) {
                *(u8 *)(state + 0x137) |= 2;
                (**(void(***)(int, int, f32, int *, int))(*(int *)gRomCurveInterface + 0x8c))(
                    state, obj, lbl_803E52EC, &local_x, -1);
                *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x68);
                *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x70);
            }
        }
    }

    *(f32 *)(state + 0x120) = lbl_803E52F0;

    if (player != 0) {
        dist = Vec_distance(player + 0x18, obj + 0x18);
        *(f32 *)(state + 0x108) = dist;
        *(f32 *)(state + 0x10c) = dist;
    } else {
        *(f32 *)(state + 0x108) = lbl_803E52F4;
        *(f32 *)(state + 0x10c) = lbl_803E52F4;
    }

    ObjGroup_AddObject(obj, 0x31);
    ObjGroup_AddObject(obj, 0x47);

    if (*(short *)(obj + 0x46) == 0x658) {
        *(short *)(state + 0x134) = 0x66d;
    } else {
        *(short *)(state + 0x134) = 0xc1;
    }
}

#pragma scheduling off
#pragma peephole off
void enemymushroom_resetToSpawn(s16 *obj,float *state,int enableTimer)
{
  int objDef;
  u32 randomValue;

  objDef = *(int *)((u8 *)obj + 0x4c);
  obj[2] = (s16)randomGetRange(-0x5dc,0x5dc);
  obj[1] = (s16)randomGetRange(-0x5dc,0x5dc);
  obj[0] = (s16)randomGetRange(-0x5dc,0x5dc);
  *(u8 *)((u8 *)obj + 0x36) = 0xff;
  obj[3] = (s16)(obj[3] & ~0x4000);
  *(f32 *)((u8 *)obj + 0xc) = *(f32 *)(objDef + 8);
  *(f32 *)((u8 *)obj + 0x10) = *(f32 *)(objDef + 0xc);
  *(f32 *)((u8 *)obj + 0x14) = *(f32 *)(objDef + 0x10);
  if (enableTimer != 0) {
    *(f32 *)((u8 *)obj + 8) = lbl_803E52F8;
    state[0] = lbl_803E52FC;
    randomValue = randomGetRange(0,100);
    state[2] = lbl_803E5300 + (f32)(s32)randomValue;
    randomValue = randomGetRange(-100,100);
    state[1] = lbl_803E5304 * (f32)(s32)randomValue + state[3];
    state[4] = state[1] / state[2];
  }
  ObjHits_EnableObject((int)obj);
  ObjHits_RefreshObjectState((int)obj);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: enemymushroom_getExtraSize
 * EN v1.0 Address: 0x801D1D58
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int enemymushroom_getExtraSize(void)
{
  return 0x3c;
}

/*
 * --INFO--
 *
 * Function: enemymushroom_getObjectTypeId
 * EN v1.0 Address: 0x801D1D60
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int enemymushroom_getObjectTypeId(int obj)
{
  return (*(byte *)(*(int *)(obj + 0x4c) + 0x1f) << 0xb) | 0x400;
}

void enemymushroom_free(int obj)
{
  (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
  ObjGroup_RemoveObject(obj,3);
}

extern void objRenderFn_8003b8f4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);
extern f32 lbl_803E5310;

#pragma scheduling off
void enemymushroom_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    void *state = *(void **)((char *)obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5310);
        ObjPath_GetPointWorldPosition(obj, 0, (char *)state + 0x20, (char *)state + 0x24, (char *)state + 0x28, 0);
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: enemymushroom_hitDetect
 * EN v1.0 Address: 0x801D1E20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_hitDetect(void)
{
}
