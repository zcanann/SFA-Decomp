/*
 * DragonRock Palace "chuka" wall-bar object (DLL 0x230; "DFP_wallbar").
 * The DLL's real object is the chuka_* family - a moving wall/floor bar
 * driven by the shared baddie state machine.
 */
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/baddie/chuka.h"
#include "main/gamebits.h"
#include "main/dll/dll_80220608_shared.h"

typedef struct ChukaPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s8 rotXByte; /* 0x18 high byte of initial rotX (<<8) */
    u8 unk19;
    s16 rotZInit; /* 0x1A initial rotZ */
    s16 barHeight; /* 0x1C model-scale height divisor (rootMotionScale) */
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} ChukaPlacement;

void chuka_render(void)
{
}

int chuka_SeqFn(void) { return 0x0; }
int chuka_getExtraSize(void) { return 0xc; }
int chuka_getObjectTypeId(void) { return 0x0; }

void chuka_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void chuka_hitDetect(int obj)
{
    GameObject* light;
    ChukaState* state = ((GameObject*)obj)->extra;
    light = (GameObject*)state->linkedObject;
    if (light == NULL) return;
    if ((light->anim.flags & 0x40) == 0) return;
    state->linkedObject = 0;
}

void chuka_update(int obj)
{

    extern u8 gChukaModeTable[];
    extern f32 lbl_803E63F8;
    extern f32 lbl_803E63FC;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int blob = *(int*)&((GameObject*)obj)->extra;
    int ch;
    int* base;
    int o;
    int i;
    int h;
    int idx;
    int cnt;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    ch = ((ChukaState*)blob)->linkedObject;
    if ((u32)ch != 0)
    {
        if (((GameObject*)ch)->anim.flags & 0x40)
        {
            ((ChukaState*)blob)->linkedObject = 0;
            return;
        }
    }
    if ((void*)ch == NULL)
    {
        base = ObjList_GetObjects(&idx, &cnt);
        for (i = idx; i < cnt; i++)
        {
            o = base[i];
            if (((GameObject*)o)->anim.seqId == 0x431)
            {
                ((ChukaState*)blob)->linkedObject = o;
                i = cnt;
            }
        }
        if (*(void**)&((ChukaState*)blob)->linkedObject == NULL)
        {
            return;
        }
    }
    ch = ((ChukaState*)blob)->linkedObject;
    (*(void (**)(int, u8*))(*((GameObject*)ch)->anim.dll + 8))(ch, gChukaModeTable);
    if (GameBit_Get(0x5e4) == 0)
    {
        ((ChukaState*)blob)->mode = 0;
    }
    else
    {
        ((ChukaState*)blob)->mode = gChukaModeTable[((ChukaState*)blob)->modeIndex];
    }
    switch (((ChukaState*)blob)->mode)
    {
    case 0:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        break;
    case 1:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    case 2:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    case 3:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0x3fff)
        {
            ((GameObject*)obj)->anim.rotZ = 0x7fff;
        }
        break;
    case 4:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0x3fff)
        {
            ((GameObject*)obj)->anim.rotZ = 0x7fff;
        }
        break;
    default:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement*)data)->barHeight;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    }
}

extern u8 gChukaModeTable[9];
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;

void chuka_init(int obj, int params)
{
    ChukaState* state = ((GameObject*)obj)->extra;
    ChukaPlacement* placement = (ChukaPlacement*)params;
    u8* modeTable;

    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    ((GameObject*)obj)->animEventCallback = chuka_SeqFn;
    state->startY = ((GameObject*)obj)->anim.localPosY;
    state->modeIndex = placement->unk19;

    if (placement->barHeight != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            lbl_803E63F8 / ((f32)placement->barHeight / lbl_803E63FC);
    }

    if (placement->rotZInit != 0)
    {
        ((GameObject*)obj)->anim.rotZ = placement->rotZInit;
    }

    ((GameObject*)obj)->objectFlags |= 0x4000;
    state->linkedObject = 0;

    modeTable = gChukaModeTable;
    {
        int i;
        for (i = 9; i != 0; i--)
        {
            *modeTable = 0;
            modeTable++;
        }
    }
}

void chuka_release(void)
{
}

void chuka_initialise(void)
{
}
