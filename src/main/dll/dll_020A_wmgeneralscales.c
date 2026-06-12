/*
 * WM_GeneralScales (DLL 0x20A) - General Scales (Krazoa Palace).
 * TU = 0x801F48C0..0x801F4C04 (wmgeneralscales_SeqFn + wmgeneralscales_*).
 */
#include "main/dll/LGT/LGTprojectedlight.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern void Obj_SetModelRenderOpAlpha(int obj, int alpha);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int newObj, int a, int b, int c, int d);
extern void ObjLink_AttachChild(int obj, int child, int p3);
extern EffectInterface** gPartfxInterface;
extern byte framesThisStep;
extern f32 lbl_803E5E98;
extern f32 lbl_803E5E9C;
extern f32 lbl_803E5EA0;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjLink_DetachChild(int* parent, int* child);

int wmgeneralscales_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    f32* state;
    int i;
    u8 buf[16];

    state = ((GameObject*)obj)->extra;
    if (*((u8*)state + 5) != 0)
    {
        int a = *((u8*)state + 5) + framesThisStep;
        if (a < 0)
        {
            a = 0;
        }
        else if (a > 0xff)
        {
            a = 0xff;
        }
        *((u8*)state + 5) = (u8)a;
        Obj_SetModelRenderOpAlpha(obj, (u8)a);
    }
    else
    {
        Obj_SetModelRenderOpAlpha(obj, 0);
    }
    for (i = 0; i < (int)animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            *((u8*)state + 4) = 1;
            break;
        case 2:
            *((u8*)state + 4) = 2;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x556, NULL, 2, -1, buf);
            Sfx_PlayFromObject(obj, 0x7b);
            Sfx_PlayFromObject(obj, 0x7c);
            *state = lbl_803E5E98;
            break;
        case 3:
            *((u8*)state + 4) = 3;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x556, NULL, 2, -1, NULL);
            Sfx_PlayFromObject(obj, 0x7b);
            Sfx_PlayFromObject(obj, 0x7c);
            *state = lbl_803E5E9C;
            break;
        case 4:
            *((u8*)state + 4) = 0;
            break;
        case 5:
            if (((GameObject*)obj)->childObjs[0] == NULL && Obj_IsLoadingLocked() != 0)
            {
                int setup = Obj_AllocObjectSetup(0x24, 0x1b8);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                *(u8*)(setup + 4) = 0x20;
                *(u8*)(setup + 5) = 4;
                *(u8*)(setup + 7) = 0xff;
                ObjLink_AttachChild(obj, Obj_SetupObject(setup, 5, -1, -1, 0), 0);
                *(f32*)(*(int*)&((GameObject*)obj)->childObjs[0] + 8) *= lbl_803E5EA0;
            }
            break;
        case 6:
            {
                int* child = ((GameObject*)obj)->childObjs[0];
                if (child != NULL)
                {
                    ObjLink_DetachChild((int*)obj, child);
                }
                break;
            }
        case 7:
            {
                u8* p = *(u8**)&((GameObject*)obj)->anim.modelInstance;
                p[0x5f] |= 0x10;
                *((u8*)state + 5) = 1;
                break;
            }
        case 8:
            {
                u8* p = *(u8**)&((GameObject*)obj)->anim.modelInstance;
                p[0x5f] &= ~0x10;
                Obj_SetModelRenderOpAlpha(obj, 0);
                *((u8*)state + 5) = 0;
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void wmgeneralscales_hitDetect(void)
{
}

void wmgeneralscales_update(void)
{
}

void wmgeneralscales_release(void)
{
}

void wmgeneralscales_initialise(void)
{
}

int wmgeneralscales_getExtraSize(void) { return 0x8; }
int wmgeneralscales_getObjectTypeId(void) { return 0x9; }

void wmgeneralscales_free(int* obj)
{
    int* p = (int*)obj[0xc8 / 4];
    if (p != NULL) ObjLink_DetachChild(obj, p);
}

extern f32 lbl_803E5EA4;
extern void objRenderFn_8003b8f4(f32);

void wmgeneralscales_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)wmgeneralscales_SeqFn;
    *(f32*)state = lbl_803E5E98;
    *(u8*)((char*)state + 4) = 1;
    *(int*)&((GameObject*)obj)->childObjs[0] = 0;
}

void wmgeneralscales_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = ((GameObject*)obj)->extra;
    if (*(u8*)((char*)state + 4) == 1) return;
    if (visible == 0) return;
    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5EA4);
}
