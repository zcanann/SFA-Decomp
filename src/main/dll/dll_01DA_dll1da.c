/* DLL 0x1DA - rolling-rock object (DIM2 / SnowHorn region). One placed
 * instance per object: render draws the rock model; init seeds the floor
 * height into extra[0] and lifts the rock up by a fixed amount; hitDetect
 * reacts to priority hit type 0xE (a fire/torch volume) by kicking the
 * rock's XZ velocity from the hit normal and playing the put-out-fire sfx;
 * update runs the rolling physics each frame (velocity damping that depends
 * on whether the rock is grounded, geometry-normal bounce, gravity fall,
 * landing on a contact object, and a floor clamp), then persists the
 * object's position. Re-split from a former multi-object TU. */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/engine_shared.h"
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int ObjHits_GetPriorityHit(int obj, void** outHitObj, int* outSphereIdx, u32* outHitVolume);
extern f32 Vec_distance(f32* a, f32* b);
extern void ObjHits_AddContactObject(int obj, int contactObj);
extern void saveGame_saveObjectPos(int obj);
extern f32 lbl_803E4AD8;
extern f32 lbl_803E4ADC;
extern f32 lbl_803E4AE0;
extern f32 lbl_803E4AE4;
extern f32 lbl_803E4AE8;
extern f32 lbl_803E4AEC;
extern f32 lbl_803E4AF0;
extern f32 lbl_803E4AF4;
extern f32 lbl_803E4AF8;
extern f32 lbl_803E4AFC;
extern f32 lbl_803E4B00;
extern const f32 lbl_803E4B04;

typedef struct Dll1DAState
{
    f32 floorHeight; /* 0x00: clamp floor, seeded at init */
    u8 grounded;     /* 0x04: rock is resting on a contact object */
    u8 unk5;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} Dll1DAState;

int dll_1DA_getExtraSize(void) { return 0x8; }
int dll_1DA_getObjectTypeId(void) { return 0x0; }

void dll_1DA_free(void)
{
}

void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4AD8);
}

void dll_1DA_hitDetect(int obj)
{

    void* hi;
    void* player;
    f32 k;
    int hit = ObjHits_GetPriorityHit(obj, &hi, NULL, NULL);
    if (hit == 0xE)
    {
        player = Obj_GetPlayerObject();
        (void)Vec_distance((float*)&((GameObject*)obj)->anim.worldPosX, (float*)((int)player + 0x18));
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)hi)->anim.velocityX * (k = lbl_803E4ADC);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)hi)->anim.velocityZ * k;
        Sfx_PlayFromObject(obj, SFXchar_puts_out_fire);
    }
}

typedef struct
{
    int hit[7];
    f32 nx;
    f32 ny;
    f32 nz;
    int pad[8];
} RockHitInfo;

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */
void dll_1DA_update(int obj)
{
    extern int objBboxFn_800640cc(int a, int b, f32 r, int c, int* out, int obj, int d, int e, int f, int g);
    extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
    extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int* out, int a, int b);
    int state;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 len;
    f32 k;
    f32 damping;
    f32 reflect;
    int hitCount;
    int floorList;
    int i;
    RockHitInfo out;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((Dll1DAState*)state)->grounded != 0)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AE0);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AE4);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
    }
    if (((GameObject*)obj)->anim.velocityX < lbl_803E4AE8 && ((GameObject*)obj)->anim.velocityX > lbl_803E4AEC &&
        ((GameObject*)obj)->anim.velocityZ < *(f32*)&lbl_803E4AE8 && ((GameObject*)obj)->anim.velocityZ > *(f32*)&lbl_803E4AEC)
    {
        ((GameObject*)obj)->anim.velocityX = (k = lbl_803E4AF0);
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, lbl_803E4AF0,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    hitCount = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E4AF4, 1, out.hit, obj, 8, -1, 0xff, 0);
    if (hitCount != 0)
    {
        vx = -((GameObject*)obj)->anim.velocityX;
        vy = -((GameObject*)obj)->anim.velocityY;
        vz = -((GameObject*)obj)->anim.velocityZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (lbl_803E4AF0 != len)
        {
            f32 s = lbl_803E4AD8 / len;
            vx = vx * s;
            vy = vy * s;
            vz = vz * s;
        }
        reflect = lbl_803E4AF8 * (vz * out.nz + (vx * out.nx + vy * out.ny));
        ((GameObject*)obj)->anim.velocityX = out.nx * reflect;
        ((GameObject*)obj)->anim.velocityY = out.ny * reflect;
        ((GameObject*)obj)->anim.velocityZ = out.nz * reflect;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - vx;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - vy;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - vz;
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (damping = lbl_803E4AFC * len);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (lbl_803E4ADC * len);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * damping;
    }
    ((GameObject*)obj)->anim.localPosY = -(lbl_803E4B00 * timeDelta - ((GameObject*)obj)->anim.localPosY);
    hitCount = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ,
                             &floorList, 0, 0x11);
    ((Dll1DAState*)state)->grounded = 0;
    i = 0;
    for (; hitCount > 0; hitCount--)
    {
        if (((GameObject*)obj)->anim.localPosY < *(f32*)&lbl_803E4B04 + **(f32**)(floorList + i * 4))
        {
            ((GameObject*)obj)->anim.localPosY = **(f32**)(floorList + i * 4);
            ObjHits_AddContactObject(*(int*)(*(int*)(floorList + i * 4) + 0x10), obj);
            ((Dll1DAState*)state)->grounded = 1;
            break;
        }
        i++;
    }
    if (((GameObject*)obj)->anim.localPosY < *(f32*)state)
    {
        ((GameObject*)obj)->anim.localPosY = *(f32*)state;
    }
    saveGame_saveObjectPos(obj);
}

void dll_1DA_init(void* obj)
{
    *(*(f32**)&((GameObject*)obj)->extra) = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E4AD8;
}

void dll_1DA_release(void)
{
}

void dll_1DA_initialise(void)
{
}
