/* DLL 0x10E - DeathSeq [8018BC48-8018BC50) */
#include "main/objseq.h"

extern f32 timeDelta;

#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"

extern s16* Camera_GetCurrentViewSlot(void);
extern void setScreenTransitionPause(int v);
extern void addButtonObject(int* obj);
extern f32 lbl_803E3D1C;
extern f32 lbl_803E3D58;
extern f32 lbl_803E3D2C;

extern void setPendingMapLoad(int v);
extern void removeButtonObject(int* obj);
extern int fn_80296C5C(void);
extern void fn_80296C6C(int* player, int v);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int streamId, void* cb);
extern void cutsceneFadeInOut(int v);
extern void Obj_FreeObject(int* obj);
extern void showDeathMenu(void);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void Camera_SetFovY(f32 fov);
extern void Rcp_SetViewFinderHudEnabled(int v);
extern f32 lbl_803E3D18;
extern f32 lbl_803E3D20;
extern f32 lbl_803E3D24;
extern f32 lbl_803E3D28;
extern f32 lbl_803E3D30;
extern f32 lbl_803E3D34;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D40;
extern f32 lbl_803E3D44;
extern f32 lbl_803E3D48;

void deathseq_init(int* obj)
{
    f32* state = ((GameObject*)obj)->extra;
    s16* cam = Camera_GetCurrentViewSlot();
    f32 f;

    setScreenTransitionPause(1);
    (*gScreenTransitionInterface)->start(1, 1);
    ObjAnim_SetCurrentMove((int)obj, 0x8e, lbl_803E3D1C, 0);
    state[0] = lbl_803E3D58;
    state[1] = ((GameObject*)cam)->anim.localPosX;
    state[2] = ((GameObject*)cam)->anim.localPosY;
    state[3] = ((GameObject*)cam)->anim.localPosZ;
    *(int*)(state + 6) = cam[0];
    *(int*)(state + 7) = cam[1];
    f = lbl_803E3D2C;
    state[4] = f;
    state[5] = f;
    addButtonObject(obj);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x400);
}

void deathseq_render(void)
{
}

void deathseq_hitDetect(void)
{
}

void deathseq_release(void)
{
}

void deathseq_initialise(void)
{
}

void dll_127_free_nop(void);

int deathseq_getExtraSize(void) { return 0x24; }
int deathseq_getObjectTypeId(void) { return 0x0; }
int dll_127_getExtraSize_ret_0(void);

void deathseq_free(int* obj)
{
    setScreenTransitionPause(0);
    setPendingMapLoad(0);
    removeButtonObject(obj);
}

void deathgas_init(int* obj);

typedef struct
{
    f32 timer; // 0x0
    f32 camX; // 0x4
    f32 camY; // 0x8
    f32 camZ; // 0xc
    f32 dist; // 0x10
    f32 distTarget; // 0x14
    int camRotY; // 0x18
    int camRotX; // 0x1c
    u8 menuShown : 1; // 0x20 bit 7
    u8 camActive : 1; // bit 6
    u8 transitionStarted : 1; // bit 5
} DeathSeqState;

void deathseq_update(int* obj)
{
    extern int* Obj_GetPlayerObject(void);
    s16* cam = Camera_GetCurrentViewSlot();
    DeathSeqState* state = ((GameObject*)obj)->extra;
    int ready;
    int* player = Obj_GetPlayerObject();
    ObjTextureRuntimeSlot* tex;

    ready = 0;
    if (fn_80296C5C() != 0)
    {
        state->distTarget = lbl_803E3D18;
        if (((GameObject*)obj)->anim.currentMove != 0x92)
        {
            AudioStream_StopCurrent();
            AudioStream_Play(0x51e1, AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove((int)obj, 0x92, lbl_803E3D1C, 0);
        }
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3D20, timeDelta, NULL);
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture(obj, 5, 0);
            tex->textureId = 0;
            tex = objFindTexture(obj, 4, 0);
            tex->textureId = 0;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3D28)
        {
            if (!state->transitionStarted)
            {
                setScreenTransitionPause(0);
                (*gScreenTransitionInterface)->step(10, 1);
                state->transitionStarted = 1;
            }
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                if (player != NULL)
                {
                    fn_80296C6C(player, 0);
                }
                cutsceneFadeInOut(0);
                setPendingMapLoad(0);
                Obj_FreeObject(obj);
            }
        }
        else
        {
            ready = 1;
        }
    }
    else
    {
        state->distTarget = lbl_803E3D2C;
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3D20, timeDelta, NULL);
            ready = 1;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture(obj, 5, 0);
            tex->textureId = 0x200;
            tex = objFindTexture(obj, 4, 0);
            tex->textureId = 0x200;
        }
        state->timer -= timeDelta;
        if (state->timer <= *(f32*)&lbl_803E3D1C)
        {
            state->timer = lbl_803E3D1C;
            if (!state->menuShown)
            {
                showDeathMenu();
                state->menuShown = 1;
            }
        }
    }

    if (ready != 0)
    {
        f32 cos30 = mathSinf(lbl_803E3D30);
        f32 sin30 = mathCosf(lbl_803E3D30);
        f32 sin34 = mathCosf(lbl_803E3D34);
        f32 cos34 = mathSinf(lbl_803E3D34);
        f32 xTerm;
        f32 negSin;
        f32 fz;
        f32 zTerm;
        f32 dz = state->dist * cos34;
        sin34 = state->dist * sin34;
        sin30 = sin34 * sin30;
        sin34 = sin34 * cos30;
        cam[0] = 0x2000;
        cam[1] = 0x1000;
        xTerm = lbl_803E3D38 * -mathSinf((lbl_803E3D3C * (f32) * (s16*)obj) / lbl_803E3D40);
        negSin = -mathCosf((lbl_803E3D3C * (f32) * (s16*)obj) / lbl_803E3D40);
        zTerm = (fz = lbl_803E3D38) * negSin;
        ((GameObject*)cam)->anim.localPosX = sin30 + (((GameObject*)obj)->anim.worldPosX + xTerm);
        ((GameObject*)cam)->anim.localPosY = (fz + ((GameObject*)obj)->anim.worldPosY) + dz;
        ((GameObject*)cam)->anim.localPosZ = sin34 + (((GameObject*)obj)->anim.worldPosZ + zTerm);
        Camera_SetFovY(lbl_803E3D44);
        state->camActive = 1;
        state->dist += interpolate(state->distTarget - state->dist, lbl_803E3D48, timeDelta);
        Rcp_SetViewFinderHudEnabled(0);
    }
    else
    {
        cam[0] = state->camRotY;
        cam[1] = state->camRotX;
        ((GameObject*)cam)->anim.localPosX = state->camX;
        ((GameObject*)cam)->anim.localPosY = state->camY;
        ((GameObject*)cam)->anim.localPosZ = state->camZ;
        state->camActive = 0;
    }

    if (state->camActive)
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~0x4000;
    }
    else
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | 0x4000;
    }
}
