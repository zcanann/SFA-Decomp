#include "main/audio/sfx_ids.h"
#include "main/dll/NW/dll_1DB.h"
#include "main/game_object.h"

typedef struct EdiblemushroomPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
} EdiblemushroomPlacement;


typedef struct EdiblemushroomState
{
    u8 pad0[0x108 - 0x0];
    f32 unk108;
    f32 unk10C;
    u8 pad110[0x134 - 0x110];
    s16 eventId;
    u8 pad136[0x138 - 0x136];
} EdiblemushroomState;


extern f32 lbl_803E52A8;

extern u8* Obj_GetPlayerObject(void);
extern u8* getTrickyObject(void);
extern int objIsFrozen(u8 * self);
extern void ObjHits_DisableObject(u8 * obj);
extern void gameBitIncrement(s16 bit);
extern void GameBit_Set(int bit, int value);
extern void itemPickupDoParticleFx(u8* obj, f32 scale, int mode, int count);
extern void Sfx_PlayFromObject(u8* obj, int sfxId);
extern int ObjMsg_Pop(u8* obj, int* outMsg, int a, int b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern void Obj_StartModelFadeIn(u8* obj, int frames);
extern void Obj_SetModelColorFadeRecursive(u8* obj, int a, int b, int c, int d, int e);
extern int ObjHits_GetPriorityHit(u8* obj, int* outOther, int a, int b);
extern void edibleMushroomFn_801d083c(u8 * self, u8 * state, u8 * other);
extern f32 sqrtf(f32 x);


/*
 * --INFO--
 *
 * Function: ediblemushroom_update
 * EN v1.0 Address: 0x801D16EC
 * EN v1.0 Size: 652b
 */
void ediblemushroom_update(u8* self)
{
    u8* state;
    u8* other;
    u8* player;
    u8* enemy;
    int hitObj;
    int msg;
    int hitKind;
    f32 distState;
    f32 distEnemy;

    state = (u8*)*(int*)&((GameObject*)self)->extra;
    other = (u8*)*(int*)&((GameObject*)self)->anim.placementData;
    player = Obj_GetPlayerObject();
    enemy = getTrickyObject();

    if (objIsFrozen(self) != 0) goto end;

    if (state[0x136] == 8)
    {
        while (ObjMsg_Pop(self, &msg, 0, 0) != 0)
        {
            if (((u32)msg - 0x70000) != 0xB) continue;
            ((GameObject*)self)->anim.flags = (s16)(((GameObject*)self)->anim.flags | 0x4000);
            ObjHits_DisableObject(self);
            gameBitIncrement(((EdiblemushroomState*)state)->eventId);
            GameBit_Set(0x12E, 0);
            if (((GameObject*)self)->anim.seqId == 0x658)
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 0xFF, 0x28);
            }
            else
            {
                itemPickupDoParticleFx(self, lbl_803E52A8, 6, 0x28);
            }
            Sfx_PlayFromObject(self, SFXen_waterblock_stop);
        }
        goto end;
    }

    if (state[0x139] != 0)
    {
        ((GameObject*)self)->anim.localPosX = ((EdiblemushroomPlacement*)other)->unk8;
        ((GameObject*)self)->anim.localPosY = ((EdiblemushroomPlacement*)other)->unkC;
        ((GameObject*)self)->anim.localPosZ = ((EdiblemushroomPlacement*)other)->unk10;
        ((GameObject*)self)->anim.alpha = 0xFF;
        state[0x139] = 0;
    }

    ((EdiblemushroomState*)state)->unk10C = ((EdiblemushroomState*)state)->unk108;
    distState = vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(self + 0x18));
    if (enemy == NULL)
    {
        ((EdiblemushroomState*)state)->unk108 = sqrtf(distState);
    }
    else
    {
        distEnemy = vec3f_distanceSquared((f32*)(enemy + 0x18), (f32*)(self + 0x18));
        if (distState < distEnemy)
        {
            ((EdiblemushroomState*)state)->unk108 = sqrtf(distState);
        }
        else
        {
            ((EdiblemushroomState*)state)->unk108 = sqrtf(distEnemy);
        }
        if (((EdiblemushroomState*)state)->unk108 < (f32)(u32)other[0x1F]
        )
        {
            (*(void (**)(u8*, u8*, int, int))(*(int*)*(int*)(enemy + 0x68) + 0x28))
                (enemy, self, 0, 1);
        }
    }

    hitKind = ObjHits_GetPriorityHit(self, &hitObj, 0, 0);
    if (hitKind != 0)
    {
        if (hitKind == 0x10)
        {
            Obj_StartModelFadeIn(self, 0x12C);
        }
        else
        {
            Obj_SetModelColorFadeRecursive(self, 0xF, 0xC8, 0, 0, 1);
            if (*(s16*)((u8*)hitObj + 0x46) != 0x416)
            {
                if ((state[0x137] & 0x10) == 0)
                {
                    Sfx_PlayFromObject(self, SFXmv_curtainloop16);
                }
                state[0x137] = (u8)(state[0x137] | 0x10);
            }
        }
    }
    edibleMushroomFn_801d083c(self, state, other);

end:
    ;
}

