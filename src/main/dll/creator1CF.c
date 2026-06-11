#include "main/dll/creator1CF.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"

extern void* Camera_GetCurrentViewSlot(void);
extern float sqrtf(float x);
extern int randomGetRange(int min, int max);
extern void voxmaps_worldToGrid(void* world, void* grid);
extern int voxmaps_traceLine(void* from, void* to, void* out, int param4, int param5);

extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern u8 framesThisStep;
extern f32 lbl_803E51C8;
extern f32 lbl_803E51CC;
extern f32 lbl_803E51D0;
extern f32 lbl_803E51D4;
extern f32 lbl_803E51D8;
extern f32 lbl_803E51DC;

/*
 * --INFO--
 *
 * Function: dll_19E_free
 * EN v1.0 Address: 0x801CCFB4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CCFE4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19E_free(int param_1)
{
    (*gModgfxInterface)->detachSource((void*)param_1);
    (*gExpgfxInterface)->freeSource2((u32)param_1);
}

/*
 * --INFO--
 *
 * Function: dll_19E_render
 * EN v1.0 Address: 0x801CD008
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801CD0F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19E_render(int obj, int param_2, int param_3, int param_4,
                    int param_5, s8 visible)
{
    int state;
    u8* camera;
    f32 dist;
    f32 invDist;
    f32 facz, facy, facx;
    f32 facz2, facy2, facx2;
    f32 nz, ny, nx;
    struct
    {
        f32 delta[3];

        struct
        {
            u8 pad[0xc];
            f32 x, y, z;
        } args;
    } stk;
    f32 midA[3];
    f32 midB[3];
    f32 gridA[2];
    f32 gridB[2];
    int traceOut[2];

    state = *(int*)&((GameObject*)obj)->extra;
    if (visible == 0)
    {
        *(s16*)(state + 4) = 0;
        *(u8*)(state + 0xa) = 0;
    }
    else if (*(u8*)(state + 0xc) != 0)
    {
        *(u8*)(state + 0xa) = 1;
        camera = (u8*)Camera_GetCurrentViewSlot();
        stk.delta[0] = *(f32*)(camera + 0xc) - ((GameObject*)obj)->anim.localPosX;
        stk.delta[1] = *(f32*)(camera + 0x10) - ((GameObject*)obj)->anim.localPosY;
        stk.delta[2] = *(f32*)(camera + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        dist = sqrtf(stk.delta[2] * stk.delta[2] + (stk.delta[0] * stk.delta[0] + stk.delta[1] * stk.delta[1]));
        if (dist > lbl_803E51C8)
        {
            invDist = lbl_803E51CC / dist;
            nx = stk.delta[0] * invDist;
            stk.delta[0] = nx;
            ny = stk.delta[1] * invDist;
            stk.delta[1] = ny;
            nz = stk.delta[2] * invDist;
            stk.delta[2] = nz;
            facx = lbl_803E51D0 * nx;
            midA[0] = facx;
            facy = lbl_803E51D0 * ny;
            midA[1] = facy;
            facz = lbl_803E51D0 * nz;
            midA[2] = facz;
            midA[0] = facx + ((GameObject*)obj)->anim.localPosX;
            midA[1] = facy + ((GameObject*)obj)->anim.localPosY;
            midA[2] = facz + ((GameObject*)obj)->anim.localPosZ;
            facx2 = lbl_803E51D4 * nx;
            midB[0] = facx2;
            facy2 = lbl_803E51D4 * ny;
            midB[1] = facy2;
            facz2 = lbl_803E51D4 * nz;
            midB[2] = facz2;
            midB[0] = facx2 + *(f32*)(camera + 0xc);
            midB[1] = facy2 + *(f32*)(camera + 0x10);
            midB[2] = facz2 + *(f32*)(camera + 0x14);
            voxmaps_worldToGrid(midA, gridA);
            voxmaps_worldToGrid(midB, gridB);
            if (voxmaps_traceLine(gridA, gridB, traceOut, 0, 0) == 0)
            {
                *(u8*)(state + 0xa) = 0;
                (*gExpgfxInterface)->freeSource(obj);
            }
        }
        if (*(s16*)(state + 4) > 0)
        {
            *(s16*)(state + 4) -= framesThisStep;
        }
        else
        {
            if (*(u8*)(state + 0xa) != 0)
            {
                stk.args.x = lbl_803E51D8;
                stk.args.y = lbl_803E51DC;
                stk.args.z = lbl_803E51D8;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &stk.args, 0x12, -1, NULL);
            }
            *(s16*)(state + 4) = (s16)(randomGetRange(-10, 10) + 0x3c);
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_hitDetect(void)
{
}
