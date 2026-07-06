/*
 * WM_GeneralScales (DLL 0x20A) - General Scales at Krazoa Palace, the
 * cutscene actor driven entirely by sequence events (his appearance in
 * the final spirit ceremony). TU = 0x801F48C0..0x801F4C04
 * (wmgeneralscales_SeqFn + wmgeneralscales_*).
 *
 * The SeqFn fades the model in/out through state->fadeAlpha, spawns
 * impact particles + sfx on the slam events, and attaches/detaches his
 * 'scalessword' child object on demand. He starts hidden (phase 1
 * skips render).
 */
#include "main/dll/LGT/LGTprojectedlight.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

/* phase values written by the SeqFn (author comment: 1 = hidden,
   2/3 = slam variants, 0 = idle). SLAM0/SLAM1 are neutral names - the
   comment does not distinguish what 2 vs 3 mean. */
#define WMGENERALSCALES_PHASE_IDLE 0
#define WMGENERALSCALES_PHASE_HIDDEN 1
#define WMGENERALSCALES_PHASE_SLAM0 2
#define WMGENERALSCALES_PHASE_SLAM1 3

/* per-object extra state (getExtraSize == 0x8). unk00 is written here
   (0.0 / 800.0 on the slam events) but only read by other TUs. */
typedef struct WmGeneralScalesState
{
    f32 unk00;    /* 0x00 */
    u8 phase;     /* 0x04: 1 = hidden, 2/3 = slam variants, 0 = idle */
    u8 fadeAlpha; /* 0x05: 0 = invisible; ramps by framesThisStep while set */
    u8 pad06[2];
} WmGeneralScalesState;

STATIC_ASSERT(sizeof(WmGeneralScalesState) == 0x8);

/* romlist object type of the sword child (retail 'scalessword') */
#define WMGENERALSCALES_SWORD_OBJECT_TYPE 0x1B8

extern void Obj_SetModelRenderOpAlpha(int obj, int alpha);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int newObj, int a, int b, int c, int d);
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern u8 framesThisStep;
extern f32 lbl_803E5E98; /* 0.0 */
extern f32 lbl_803E5E9C; /* 800.0 */
extern f32 lbl_803E5EA0; /* 1.1: sword scale-up */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjLink_DetachChild(int* parent, int* child);
extern f32 lbl_803E5EA4; /* 1.0: render scale */
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

int wmgeneralscales_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WmGeneralScalesState* state;
    int i;
    u8 buf[16];

    state = ((GameObject*)obj)->extra;
    if (state->fadeAlpha != 0)
    {
        int a = state->fadeAlpha + framesThisStep;
        if (a < 0)
        {
            a = 0;
        }
        else if (a > 0xff)
        {
            a = 0xff;
        }
        state->fadeAlpha = a;
        Obj_SetModelRenderOpAlpha(obj, (u8)a);
    }
    else
    {
        Obj_SetModelRenderOpAlpha(obj, 0);
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1: /* hide */
            state->phase = WMGENERALSCALES_PHASE_HIDDEN;
            break;
        case 2: /* slam, tracked fx */
            state->phase = WMGENERALSCALES_PHASE_SLAM0;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x556, NULL, 2, -1, buf);
            Sfx_PlayFromObject(obj, 0x7b);
            Sfx_PlayFromObject(obj, 0x7c);
            state->unk00 = lbl_803E5E98;
            break;
        case 3: /* slam variant */
            state->phase = WMGENERALSCALES_PHASE_SLAM1;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x556, NULL, 2, -1, NULL);
            Sfx_PlayFromObject(obj, 0x7b);
            Sfx_PlayFromObject(obj, 0x7c);
            state->unk00 = lbl_803E5E9C;
            break;
        case 4: /* back to idle */
            state->phase = WMGENERALSCALES_PHASE_IDLE;
            break;
        case 5: /* draw the sword: spawn + attach a scalessword child */
            if (((GameObject*)obj)->childObjs[0] == NULL && Obj_IsLoadingLocked() != 0)
            {
                int setup = Obj_AllocObjectSetup(0x24, WMGENERALSCALES_SWORD_OBJECT_TYPE);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                ((ObjPlacement*)setup)->color[0] = 0x20;
                ((ObjPlacement*)setup)->color[1] = 4;
                ((ObjPlacement*)setup)->color[3] = 0xff;
                ObjLink_AttachChild(obj, Obj_SetupObject(setup, 5, -1, -1, 0), 0);
                *(f32*)(*(int*)&((GameObject*)obj)->childObjs[0] + 8) *= lbl_803E5EA0;
            }
            break;
        case 6: /* sheathe: detach the sword child */
            {
                int* child = ((GameObject*)obj)->childObjs[0];
                if (child != NULL)
                {
                    ObjLink_DetachChild((int*)obj, child);
                }
                break;
            }
        case 7: /* begin fade-in (model flag + alpha ramp from 1) */
            {
                u8* p = *(u8**)&((GameObject*)obj)->anim.modelInstance;
                p[0x5f] |= 0x10;
                state->fadeAlpha = 1;
                break;
            }
        case 8: /* end fade: clear the flag, fully invisible */
            {
                u8* p = *(u8**)&((GameObject*)obj)->anim.modelInstance;
                p[0x5f] &= ~0x10;
                Obj_SetModelRenderOpAlpha(obj, 0);
                state->fadeAlpha = 0;
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int wmgeneralscales_getExtraSize(void) { return sizeof(WmGeneralScalesState); }
int wmgeneralscales_getObjectTypeId(void) { return 0x9; }

void wmgeneralscales_free(int* obj)
{
    int* p = (int*)obj[0xc8 / 4]; /* childObjs[0] */
    if (p != NULL) ObjLink_DetachChild(obj, p);
}

void wmgeneralscales_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    WmGeneralScalesState* state = ((GameObject*)obj)->extra;
    if (state->phase == WMGENERALSCALES_PHASE_HIDDEN) return;
    if (visible == 0) return;
    ((void(*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E5EA4);
}

void wmgeneralscales_hitDetect(void)
{
}

void wmgeneralscales_update(void)
{
}

void wmgeneralscales_init(int* obj)
{
    WmGeneralScalesState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = wmgeneralscales_SeqFn;
    state->unk00 = lbl_803E5E98;
    state->phase = WMGENERALSCALES_PHASE_HIDDEN;
    *(int*)&((GameObject*)obj)->childObjs[0] = 0;
}

void wmgeneralscales_release(void)
{
}

void wmgeneralscales_initialise(void)
{
}
