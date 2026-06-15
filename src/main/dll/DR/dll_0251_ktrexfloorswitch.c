#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct KtrexfloorswitchPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x19 - 0x14];
    u8 unk19;
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 unk1F;
} KtrexfloorswitchPlacement;


typedef struct KtrexfloorswitchSpawnEnergyArcState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
} KtrexfloorswitchSpawnEnergyArcState;


typedef struct KtrexfloorswitchState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 pad6[0x8 - 0x6];
    f32 unk8;
    f32 unkC;
    u8 unk10;
    u8 pad11[0x14 - 0x11];
} KtrexfloorswitchState;

void ktrexfloorswitch_free(void)
{
}

int ktrexfloorswitch_getExtraSize(void) { return 0x14; }

int ktrexfloorswitch_getObjectTypeId(void) { return 0x0; }

void ktrexfloorswitch_hitDetect(void)
{
}

void ktrexfloorswitch_initialise(void)
{
}

void ktrexfloorswitch_release(void)
{
}

void ktrexfloorswitch_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6858);
    }
}

void ktrexfloorswitch_init(int obj, char* arg)
{
    char* p = ((GameObject*)obj)->extra;
    int r;
    *(s16*)obj = (s16)(((u8*)arg)[0x18] << 8);
    ((KtrexfloorswitchState*)p)->unk8 = (f32)(u32)((u8*)arg)[0x19];
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->unkF8 = 1;
    {
        KtrexfloorswitchPlacement* pl =
            (KtrexfloorswitchPlacement*)*(int*)&((GameObject*)obj)->anim.placementData;
        r = (*gRomCurveInterface)->find(&lbl_803DC2A0, 1, 0, pl->unk8, pl->unkC, pl->unk10);
    }
    if (r != -1)
    {
        r = (int)(*gRomCurveInterface)->getById(r);
        if ((u32)r != 0)
        {
            ((GameObject*)obj)->anim.localPosX = *(f32*)(r + 0x8);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)(r + 0x10);
        }
    }
}

void ktrexfloorswitch_spawnEnergyArc(int obj, f32 scale, int angle)
{
    char* runtime = ((GameObject*)obj)->extra;
    f32 pos[3];
    f32 dir[3];
    if (*(void**)(runtime + 0x10) != 0)
    {
        mm_free(*(void**)(runtime + 0x10));
        *(void**)(runtime + 0x10) = 0;
    }
    pos[0] = ((GameObject*)obj)->anim.localPosX;
    pos[1] = ((GameObject*)obj)->anim.localPosY;
    pos[2] = ((GameObject*)obj)->anim.localPosZ;
    dir[0] = lbl_803E6898;
    {
        f32 fr = (f32)angle;
        fr = fr * ((KtrexfloorswitchSpawnEnergyArcState*)runtime)->unkC;
        dir[1] = -(fr * lbl_803E689C);
    }
    dir[2] = scale;
    vecRotateZXY(obj, dir);
    dir[0] += ((GameObject*)obj)->anim.localPosX;
    dir[1] += ((GameObject*)obj)->anim.localPosY;
    dir[2] += ((GameObject*)obj)->anim.localPosZ;
    ((KtrexfloorswitchSpawnEnergyArcState*)runtime)->unk8 = (f32)(int)
    randomGetRange(10, angle);
    *(void**)(runtime + 0x10) = lightningCreate(pos, dir, lbl_803E68A0, lbl_803E68A4, (u16)angle, 96, 0);
}

typedef struct Vec3Blob
{
    int x;
    int y;
    int z;
} Vec3Blob;

void ktrexfloorswitch_update(int obj)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    int* state = ((GameObject*)obj)->extra;
    ObjTextureRuntimeSlot* tex;
    int* player;
    int anim;
    int level;
    int scroll;
    f32 vecA[3];
    f32 vecB[3];
    f32 mtx[12];
    f32 height;
    f32 xLo, xHi, zLo, zHi, cx, cz, sumX, sumZ;
    *(Vec3Blob*)vecA = *(Vec3Blob*)lbl_802C2560;
    *(Vec3Blob*)vecB = *(Vec3Blob*)lbl_802C256C;
    ((GameObject*)obj)->unkF8 = ((GameObject*)obj)->unkF4;
    ((GameObject*)obj)->unkF4 = GameBit_Get(((KtrexfloorswitchPlacement*)sub)->unk1C);
    tex = objFindTexture((void*)obj, 0, 0);
    anim = 0;
    if (((GameObject*)obj)->unkF4 <= 1)
    {
        tex->textureId = 0;
        if (((GameObject*)obj)->unkF4 == 0 && ((GameObject*)obj)->unkF8 != 0)
        {
            ((KtrexfloorswitchState*)state)->unk10 |= 0x4;
        }
        if (((GameObject*)obj)->unkF4 != 0 && ((GameObject*)obj)->unkF8 == 0)
        {
            int cp;
            ((KtrexfloorswitchState*)state)->unk10 |= 0x2;
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)sub)->unkC - (f32)(u32)(
                (KtrexfloorswitchPlacement*)sub)->unk1F;
            cp = (*gRomCurveInterface)->find(
                &lbl_803DC2A0, 1, GameBit_Get(0x572) >> 1, *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8),
                *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc),
                *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10));
            if (cp != -1)
            {
                void* res = (*gRomCurveInterface)->getById(cp);
                if (res != NULL)
                {
                    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)res + 0x8);
                    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)res + 0x10);
                }
            }
        }
        if ((((KtrexfloorswitchState*)state)->unk10 & 0x6) == 0)
        {
            return;
        }
    }
    else
    {
        if (((GameObject*)obj)->unkF8 == 0)
        {
            tex->textureId = 0x100;
            ((KtrexfloorswitchState*)state)->unk10 &= ~1;
        }
        else
        {
            int cp;
            ((KtrexfloorswitchState*)state)->unk10 |= 0x2;
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)sub)->unkC - (f32)(u32)(
                (KtrexfloorswitchPlacement*)sub)->unk1F;
            cp = (*gRomCurveInterface)->find(
                &lbl_803DC2A0, 1, GameBit_Get(0x572) >> 1, *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8),
                *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc),
                *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10));
            if (cp != -1)
            {
                void* res = (*gRomCurveInterface)->getById(cp);
                if (res != NULL)
                {
                    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)res + 0x8);
                    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)res + 0x10);
                }
            }
        }
    }
    ((KtrexfloorswitchState*)state)->unk4 -= 1;
    if ((s8)((KtrexfloorswitchState*)state)->unk4 < 0)
    {
        ((KtrexfloorswitchState*)state)->unk4 = 0;
    }
    if ((s8) * (s8*)(*(int*)((char*)obj + 0x58) + 0x10f) > 0 && ((GameObject*)obj)->unkF4 == 2)
    {
        player = (int*)Obj_GetPlayerObject();
        if (player != 0)
        {
            PSMTXRotRad(mtx, 0x79, (f32)(lbl_803E6860 * (f64) * (s16*)obj / lbl_803E6868));
            PSMTXMultVecSR(mtx, vecA, vecA);
            PSMTXMultVecSR(mtx, vecB, vecB);
            cx = ((GameObject*)obj)->anim.localPosX;
            sumX = vecB[0] + (cx + vecA[0]);
            if (sumX < cx)
            {
                xHi = cx;
                xLo = sumX;
            }
            else
            {
                xHi = sumX;
                xLo = cx;
            }
            cz = ((GameObject*)obj)->anim.localPosZ;
            sumZ = vecB[2] + (cz + vecA[2]);
            if (sumZ < cz)
            {
                zHi = cz;
                zLo = sumZ;
            }
            else
            {
                zHi = sumZ;
                zLo = cz;
            }
            xLo += lbl_803E6870;
            xHi -= lbl_803E6870;
            zLo += lbl_803E6870;
            zHi -= lbl_803E6870;
            if (((GameObject*)player)->anim.localPosX >= xLo && ((GameObject*)player)->anim.localPosX <= xHi &&
                ((GameObject*)player)->anim.localPosZ >= zLo && ((GameObject*)player)->anim.localPosZ <= zHi)
            {
                ((KtrexfloorswitchState*)state)->unk4 = 5;
            }
        }
    }
    if ((((KtrexfloorswitchState*)state)->unk10 & 0x4) != 0)
    {
        height = ((KtrexfloorswitchPlacement*)sub)->unkC - (f32)(u32)((KtrexfloorswitchPlacement*)sub)->unk1F;
        if (((GameObject*)obj)->anim.localPosY > height)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E6874 * timeDelta;
            if (((GameObject*)obj)->anim.localPosY <= height)
            {
                ((GameObject*)obj)->anim.localPosY = height;
                ((KtrexfloorswitchState*)state)->unk10 &= ~0x4;
            }
            else
            {
                anim = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x488, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((((KtrexfloorswitchState*)state)->unk10 & 0x2) != 0)
    {
        if (((GameObject*)obj)->anim.localPosY < ((KtrexfloorswitchPlacement*)sub)->unkC)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E6874 * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY >= ((KtrexfloorswitchPlacement*)sub)->unkC)
            {
                ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)sub)->unkC;
                ((KtrexfloorswitchState*)state)->unk10 &= ~0x2;
            }
            else
            {
                anim = 1;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x488, NULL, 2, -1, NULL);
            }
        }
    }
    else if ((s8)((KtrexfloorswitchState*)state)->unk4 != 0 && (((KtrexfloorswitchState*)state)->unk10 & 1) == 0)
    {
        height = ((KtrexfloorswitchPlacement*)sub)->unkC - (f32)(u32)((KtrexfloorswitchPlacement*)sub)->unk1E;
        if (((GameObject*)obj)->anim.localPosY > height)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E6878 * timeDelta;
            if (((GameObject*)obj)->anim.localPosY < height)
            {
                ((GameObject*)obj)->anim.localPosY = height;
            }
            else
            {
                anim = 1;
            }
        }
        if (((KtrexfloorswitchState*)state)->unk8 < lbl_803E687C)
        {
            ((KtrexfloorswitchState*)state)->unk8 = (f32)(u32)((KtrexfloorswitchPlacement*)sub)->unk19;
            level = GameBit_Get(((KtrexfloorswitchPlacement*)sub)->unk1A) & 0xff;
            if (level < 0xf)
            {
                level += 1;
                GameBit_Set(((KtrexfloorswitchPlacement*)sub)->unk1A, level);
                if (level == 0xf)
                {
                    ((KtrexfloorswitchState*)state)->unk10 |= 0x8;
                }
            }
            else
            {
                ((KtrexfloorswitchState*)state)->unk10 &= ~0x8;
                ((KtrexfloorswitchState*)state)->unk10 |= 1;
                GameBit_Set(((KtrexfloorswitchPlacement*)sub)->unk1A, 0);
                if (GameBit_Get(0x55a) != 0)
                {
                    GameBit_Set(0x55a, 0);
                    GameBit_Set(0x55b, 1);
                }
                else
                {
                    GameBit_Set(0x55a, 1);
                    GameBit_Set(0x55b, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
        }
        ((KtrexfloorswitchState*)state)->unk8 -= timeDelta;
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = lbl_803E6878 * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > ((KtrexfloorswitchPlacement*)sub)->unkC)
        {
            ((GameObject*)obj)->anim.localPosY = ((KtrexfloorswitchPlacement*)sub)->unkC;
        }
        else
        {
            anim = 1;
        }
        if ((((KtrexfloorswitchState*)state)->unk10 & 0x8) != 0)
        {
            if (((KtrexfloorswitchState*)state)->unk8 < lbl_803E687C)
            {
                ((KtrexfloorswitchState*)state)->unk10 &= ~0x8;
                ((KtrexfloorswitchState*)state)->unk10 |= 1;
                GameBit_Set(((KtrexfloorswitchPlacement*)sub)->unk1A, 0);
                if (GameBit_Get(0x55a) != 0)
                {
                    GameBit_Set(0x55a, 0);
                    GameBit_Set(0x55b, 1);
                }
                else
                {
                    GameBit_Set(0x55a, 1);
                    GameBit_Set(0x55b, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
            ((KtrexfloorswitchState*)state)->unk8 -= timeDelta;
        }
    }
    if ((((KtrexfloorswitchState*)state)->unk10 & 1) == 0 && (s8)((KtrexfloorswitchState*)state)->unk5 != (s8)(
        (KtrexfloorswitchState*)state)->unk4)
    {
        GameBit_Get(((KtrexfloorswitchPlacement*)sub)->unk1A);
        GameBit_Set(((KtrexfloorswitchPlacement*)sub)->unk1A, 0);
    }
    if ((s8)anim != 0 && lbl_803DDD60 == 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_bodyf2_c);
    }
    lbl_803DDD60 = (s8)anim;
    if (((GameObject*)obj)->unkF4 == 2)
    {
        if ((s8)((KtrexfloorswitchState*)state)->unk4 != 0)
        {
            if (lbl_803E687C == ((KtrexfloorswitchState*)state)->unkC)
            {
                ((KtrexfloorswitchState*)state)->unkC = lbl_803E6880;
            }
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->unkC + (f32)tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x400 - scroll;
                ((KtrexfloorswitchState*)state)->unkC = -((KtrexfloorswitchState*)state)->unkC;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x200 - scroll;
                ((KtrexfloorswitchState*)state)->unkC = -((KtrexfloorswitchState*)state)->unkC;
            }
            tex->textureId = scroll;
        }
        else
        {
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->unkC + (f32)tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x400 - scroll;
                ((KtrexfloorswitchState*)state)->unkC = -((KtrexfloorswitchState*)state)->unkC;
            }
            else if (scroll < 0x100)
            {
                scroll = 0x100;
                ((KtrexfloorswitchState*)state)->unkC = lbl_803E687C;
            }
            tex->textureId = scroll;
        }
        if ((((KtrexfloorswitchState*)state)->unk10 & 0x6) == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x486, NULL, 2, -1, NULL);
        }
    }
    else
    {
        if (tex->textureId != 0)
        {
            scroll = (int)(timeDelta * ((KtrexfloorswitchState*)state)->unkC + (f32)tex->textureId);
            if (scroll > 0x200)
            {
                scroll = 0x400 - scroll;
                ((KtrexfloorswitchState*)state)->unkC = -((KtrexfloorswitchState*)state)->unkC;
            }
            else if (scroll < 0x100)
            {
                scroll = 0;
            }
            tex->textureId = scroll;
        }
    }
    ((KtrexfloorswitchState*)state)->unk5 = ((KtrexfloorswitchState*)state)->unk4;
}
