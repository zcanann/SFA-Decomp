/*
 * DragonRock rope node (DLL 0x175; "DFropenode") - a node in the DragonRock
 * rope/cradle: it syncs the rope geometry between its endpoints, renders the
 * rope/cradle model and plays creak sfx.
 */
#include "main/game_object.h"
#include "main/dll/DF/DFbarrelanim.h"
#include "main/objlib.h"
#include "main/dll/DF/DFcradle.h"
#include "main/dll/DF/dll_196.h"

extern f32 sqrtf(f32 x);

extern f64 lbl_803E4DF0;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E18;
extern f32 lbl_803E4E1C;

extern f32 lbl_803E4E20;
extern f32 lbl_803E4E24;
extern void mm_free(void* p);
extern u32 GameBit_Get(int eventId);
extern void Sfx_PlayFromObject(int obj, int soundId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int soundId);
extern void Camera_LoadModelViewMatrix(int param_1, int param_2, int obj, f32 scale, f32 unused,
                                       int param_6);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_800795e8(void);
extern void textRenderSetupFn_80079804(void);
extern void getAmbientColor(int param_1, u8* blue, u8* green, u8* red);
extern void gxBlendFn_80078b4c(void);
extern void fn_80078740(void);
extern void selectTexture(void* texture, int param_2);
extern void setTextColor(undefined4* objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void drawFn_8005cf8c(void* matrix, void* displayList, int count);
extern int randomGetRange(int min, int max);
extern u8 framesThisStep;
extern void* lbl_803DBF48;
extern u8 lbl_80325E00[];
extern u8 lbl_80325E60[];
extern u8 lbl_802C2358[];
extern f32 lbl_803E4DF8;
extern void textureFree(void* resource);
extern void* textureLoadAsset(int assetId);
extern int lbl_803DBF40;
extern f32 lbl_803DBF50;
extern u8 lbl_803DBF58;
extern f32 lbl_803E4E28;

static inline f32 DFRope_S32AsFloat(s32 value)
{
    u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
    return (f32)(*(f64*)&bits - lbl_803E4DF0);
}

static inline f32 DFRope_S32AsFloat_SubAsFloat(s32 value)
{
    u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
    return (f32) * (f64*)&bits - (f32)lbl_803E4DF0;
}

int dfropenode_func0E(int obj, f32 worldX, f32 worldY, f32 worldZ, float* distanceOut,
                      float* phaseOut, u8* sideOut)
{
    DFropenodeExtra* extra;
    int result;
    int offset;
    int i;
    f32 localZ;
    f32 localY;
    f32 localX;
    f32 best;
    f32 phase;
    f32 x;
    f32 y;
    f32 z;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;

    extra = ((GameObject*)obj)->extra;
    if ((*(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x18) & 1) == 0)
    {
        return 0;
    }
    if (extra->linkedObj == NULL)
    {
        return 0;
    }
    if (worldX < extra->minX || worldX > extra->maxX || worldZ < extra->minZ ||
        worldZ > extra->maxZ)
    {
        return 0;
    }
    *distanceOut = lbl_803E4E1C;
    localX = worldX - ((GameObject*)obj)->anim.localPosX;
    localY = worldY - ((GameObject*)obj)->anim.localPosY;
    localZ = worldZ - ((GameObject*)obj)->anim.localPosZ;
    {
        i = 0;
        result = 0;
        offset = 0;
        best = lbl_803E4DFC;
        for (; i < extra->rope->count - 1; i++)
        {
            int node;

            x = localX;
            y = localY;
            z = localZ;
            node = (int)extra->rope->nodes + offset;
            phase = fn_801C1698(*(f32*)(node + 0), *(f32*)(node + 4), *(f32*)(node + 8),
                                *(f32*)(node + 0x34), *(f32*)(node + 0x38), *(f32*)(node + 0x3c),
                                &x, &y, &z);
            if (phase >= best && phase < lbl_803E4E18)
            {
                dx = x - localX;
                dy = y - localY;
                dz = z - localZ;
                distance = sqrtf(dx * dx + dy * dy + dz * dz);
                if (distance < *distanceOut)
                {
                    result = i + 1;
                    *distanceOut = distance;
                    *phaseOut = (f32)i + phase;
                }
            }
            offset += 0x34;
        }
    }
    if (result != 0)
    {
        if (result - 1 <= ((int)extra->rope->count >> 1))
        {
            *sideOut = 0;
        }
        else
        {
            *sideOut = 1;
        }
    }
    return result;
}

void dfropenode_render2(f32 phase, f32 force, int obj)
{
    int extra;
    s8 idx;
    f32 fraction;
    int node;

    extra = *(int*)&((GameObject*)obj)->extra;
    phase = phase - (f32)(s8)
    phase;
    idx = (s8)phase;
    fraction = phase - (f32)idx;
    node = **(int**)(extra + 0x2c) + idx * 0x34;
    *(f32*)(node + 0x1c) = force * fraction + *(f32*)(node + 0x1c);
    fraction = lbl_803E4E18 - fraction;
    node = **(int**)&((DFropenodeExtra*)extra)->rope + idx * 0x34;
    *(f32*)(node + 0x1c) = force * fraction + *(f32*)(node + 0x1c);
}

void dfropenode_modelMtxFn(f32 distance, int obj, float* phase)
{
    int extra;
    s32 raw;
    s8 idx;
    int node;
    f32 ph;
    f32 x0;
    f32 dx;
    f32 dz;
    f32 len;

    extra = *(int*)&((GameObject*)obj)->extra;
    ph = *phase;
    raw = (s32)ph;
    idx = (s8)raw;
    *phase = ph - (f32)idx;
    node = **(int**)&((DFropenodeExtra*)extra)->rope;
    x0 = *((f32*)node + idx * 13);
    node = node + idx * 0x34;
    dx = x0 - *(f32*)(node + 0x34);
    dz = *(f32*)(node + 8) - *(f32*)(node + 0x3c);
    len = sqrtf(dx * dx + dz * dz);
    distance = distance / len;
    *phase = *phase + distance;
    *phase = *phase + (f32)(s8)
    raw;
}

void dfropenode_func0B(f32 phase, int obj, float* xOut, float* yOut, float* zOut)
{
    DFropenodeExtra* extra;
    s8 idx;
    f32 x0;
    f32 dy;
    f32 dz;
    f32 fraction;
    DFRopeNode* node;
    int nodes;

    extra = ((GameObject*)obj)->extra;
    idx = (s8)phase;
    fraction = phase - (f32)idx;
    nodes = (int)extra->rope->nodes;
    node = (DFRopeNode*)(nodes + idx * 0x34);
    dy = node[1].pos[1] - node->pos[1];
    dz = node[1].pos[2] - node->pos[2];
    x0 = extra->rope->nodes[idx].pos[0];
    *xOut = (node[1].pos[0] - x0) * fraction + (((GameObject*)obj)->anim.localPosX + x0);
    *yOut = dy * fraction + (((GameObject*)obj)->anim.localPosY + extra->rope->nodes[idx].pos[1]);
    *zOut = dz * fraction + (((GameObject*)obj)->anim.localPosZ + extra->rope->nodes[idx].pos[2]);
}

#pragma scheduling on
#pragma peephole on
void dfropenode_setScale(int* obj, f32* out)
{
    int* p = (int*)obj[0xb8 / 4];
    out[0] = *(f32*)((char*)p + 0x1c);
    out[1] = *(f32*)((char*)p + 0x20);
    out[2] = *(f32*)((char*)p + 0x24);
    out[3] = *(f32*)((char*)p + 0x28);
}

#pragma scheduling off
#pragma peephole off
int dfropenode_syncRopeToEndpoints(DFropenodeObject* obj)
{
    extern int getAngle(f32 dx, f32 dz);
    DFropenodeExtra* extra;
    DFropenodeObject* endObj;
    DFropenodeObject* baseObj;
    int i;
    DFRopeLink* link;
    int flag;
    s16 angle;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;
    f32 clampY;
    f32 temp;
    f32 margin;

    baseObj = (DFropenodeObject*)(int)obj;
    flag = baseObj->definition[0x18] & 1;
    if (flag != 0)
    {
        extra = baseObj->extra;
        endObj = extra->linkedObj;
    }
    else
    {
        endObj = baseObj;
        baseObj = baseObj->extra->linkedObj;
        if (baseObj == NULL)
        {
            return 0;
        }
        extra = baseObj->extra;
    }

    if ((extra->rope == NULL) || (endObj == NULL))
    {
        return 0;
    }

    dx = endObj->posX - baseObj->posX;
    dy = endObj->posY - baseObj->posY;
    dz = endObj->posZ - baseObj->posZ;

    angle = getAngle(dx, dz);
    if (angle > 0x8000)
    {
        angle = angle - 0xffff;
    }
    if (angle < -0x8000)
    {
        angle = angle + 0xffff;
    }
    extra->angle = angle;

    length = sqrtf(dx * dx + dy * dy + dz * dz);
    length = length / (f32)(extra->rope->count - 1);
    link = extra->rope->links;
    extra->rope->damping = lbl_803E4E20;
    for (i = 0; i < extra->rope->count - 1; i++, link++)
    {
        link->restLength = length;
    }

    i = extra->rope->count - 1;
    extra->rope->nodes[i].pos[0] = dx;
    extra->rope->nodes[i].pos[1] = dy;
    extra->rope->nodes[i].pos[2] = dz;

    extra->minX = baseObj->posX;
    extra->minZ = baseObj->posZ;
    extra->maxX = endObj->posX;
    extra->maxZ = endObj->posZ;
    if (extra->minX > extra->maxX)
    {
        temp = extra->minX;
        extra->minX = extra->maxX;
        extra->maxX = temp;
    }
    if (extra->minZ > extra->maxZ)
    {
        temp = extra->minZ;
        extra->minZ = extra->maxZ;
        extra->maxZ = temp;
    }

    if (extra->minY != lbl_803E4DFC)
    {
        clampY = extra->minY - baseObj->posY;
        for (i = 0; i < extra->rope->count - 1; i++)
        {
            if (extra->rope->nodes[i].pos[1] < clampY)
            {
                extra->rope->nodes[i].pos[1] = clampY;
            }
        }
    }

    extra->minX = extra->minX - (margin = lbl_803E4E24);
    extra->minZ -= margin;
    extra->maxX += margin;
    extra->maxZ += margin;
    return 0;
}

int dfropenode_getExtraSize(void)
{
    return 0x34;
}

int dfropenode_getObjectTypeId(void)
{
    return 0;
}

void dfropenode_free(void* obj)
{
    void* node;
    int** objs;
    int count;
    int i;

    node = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject((u32)obj, 0x17);
    if (*(void**)((char*)node + 0x2c) != NULL && *(void**)((char*)node + 0x2c) != NULL)
    {
        mm_free(*(void**)((char*)node + 0x2c));
    }
    node = *(void**)node;
    if (node != NULL)
    {
        objs = (int**)ObjGroup_GetObjects(0x17, &count);
        for (i = 0; i < count; i++)
        {
            if ((void*)objs[i] == node)
            {
                (*(void (***)(void*))*(void**)((char*)node + 0x68))[17](node);
            }
        }
    }
}

typedef struct DfropenodePlacement
{
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    u8 pad19[0x1B - 0x19];
    u8 unk1B;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} DfropenodePlacement;

typedef struct DfropenodeRenderState
{
    undefined4 objAndParam;
    u8 red;
    u8 green;
    u8 blue;
} DfropenodeRenderState;

void dfropenode_render(int obj, int p2, int p3)
{
    ObjAnimComponent* objAnim;
    DFropenodeExtra* extra;
    int objDef;
    int eventId;
    int fadeAlpha;
    u32 oldAlpha;
    DFRopeNode* node;
    s16 segment;
    DfropenodeRenderState renderState;
    s16 matrix[0x30];
    f32 originalScale;

    renderState.objAndParam = (undefined4)p2;
    objAnim = &((GameObject*)obj)->anim;
    extra = ((GameObject*)obj)->extra;
    objDef = *(int*)&objAnim->placementData;
    eventId = ((DfropenodePlacement*)objDef)->unk1C;
    if ((eventId != 0) && (GameBit_Get(eventId) != 0))
    {
        oldAlpha = objAnim->alpha;
        if (oldAlpha == 0x46)
        {
            Sfx_PlayFromObject(obj, 0x476);
        }
        fadeAlpha = oldAlpha - framesThisStep;
        if (fadeAlpha <= 0)
        {
            objAnim->alpha = 0;
            return;
        }
        objAnim->alpha = (u8)fadeAlpha;
    }
    else
    {
        if (objAnim->alpha == 0)
        {
            Sfx_PlayFromObject(obj, 0x475);
        }
        if (objAnim->alpha < 0x46)
        {
            objAnim->alpha += framesThisStep;
        }
        else
        {
            objAnim->alpha = 0x46;
        }
    }

    if (((((DfropenodePlacement*)objDef)->unk18 & 1) != 0) && (*(void**)&extra->linkedObj != NULL) &&
        (extra->rope != NULL))
    {
        originalScale = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4DF8;
        Camera_LoadModelViewMatrix(0, p3, obj, lbl_803E4E18, lbl_803E4DFC, 0);
        ((GameObject*)obj)->anim.rootMotionScale = originalScale;
        textureSetupFn_800799c0();
        textRenderSetupFn_800795e8();
        textRenderSetupFn_80079804();
        if (((DfropenodePlacement*)objDef)->unk1B == 1)
        {
            renderState.red = 0xff;
            renderState.green = 0xff;
            renderState.blue = 0xff;
        }
        else
        {
            objAnim->alpha = 0xff;
            getAmbientColor(0, &renderState.blue, &renderState.green, &renderState.red);
            renderState.green = (u8)(renderState.green * 200 >> 8);
            renderState.red = (u8)(renderState.red * 0xaa >> 8);
        }
        {
            int alpha;

            if (objAnim->alpha > 0x46)
            {
                fn_80078740();
                alpha = 0xff;
            }
            else
            {
                gxBlendFn_80078b4c();
                alpha = (objAnim->alpha + objAnim->alpha) >> 1;
            }
            selectTexture((&lbl_803DBF48)[((DfropenodePlacement*)objDef)->unk1B], 0);
            setTextColor(&renderState.objAndParam, renderState.blue, renderState.green, renderState.red,
                         (u8)alpha);
        }
        node = extra->rope->nodes;
        for (segment = 0; segment < (int)(extra->rope->count - 1); segment++)
        {
            node++;
            fn_801C0BF8(lbl_80325E00, extra->angle, (node - 1)->pos, node->pos, matrix);
            drawFn_8005cf8c(matrix, lbl_802C2358, 6);
        }
        if (((DfropenodePlacement*)objDef)->unk1B == 1)
        {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x480);
            gxBlendFn_80078b4c();
            {
                int alpha;

                alpha = (u8)(objAnim->alpha + randomGetRange(0, objAnim->alpha));
                setTextColor(&renderState.objAndParam, renderState.blue, renderState.green,
                             renderState.red, alpha);
            }
            node = extra->rope->nodes;
            for (segment = 0; segment < (int)(extra->rope->count - 1); segment++)
            {
                node++;
                fn_801C0BF8(lbl_80325E60, extra->angle, (node - 1)->pos, node->pos, matrix);
                drawFn_8005cf8c(matrix, lbl_802C2358, 6);
            }
        }
    }
}

void dfropenode_hitDetect(void)
{
}

void dfropenode_update(DFropenodeObject* obj)
{
    extern s32 getAngle(f32 dx, f32 dz);
    extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
    DFropenodeExtra* extra;
    u8* objDef;
    DFropenodeObject* linkedObj;
    DFropenodeObject** objects;
    int objectCount;
    int objectIndex;
    DFropenodeObject* candidateObj;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;
    s16 angle;
    f32 temp;
    f32 baseX;
    f32 baseY;
    f32 baseZ;
    f32 linkedX;
    f32 linkedY;
    f32 linkedZ;
    f32 liftedY;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 normalLength;

    objDef = obj->definition;
    extra = obj->extra;
    if ((objDef[0x18] & 1) == 0)
    {
        return;
    }

    linkedObj = extra->linkedObj;
    if (linkedObj == NULL)
    {
        objects = (DFropenodeObject**)ObjList_GetObjects(&objectIndex, &objectCount);
        objectIndex = 0;
        while ((objectIndex < objectCount) && (linkedObj == NULL))
        {
            candidateObj = *objects;
            if ((candidateObj->objType == 0x36) &&
                ((s32)objDef[0x18] == candidateObj->definition[0x18] - 1))
            {
                linkedObj = candidateObj;
            }
            objects++;
            objectIndex++;
        }
        if (linkedObj == NULL)
        {
            return;
        }

        linkedObj->extra->linkedObj = obj;
        extra = obj->extra;
        extra->linkedObj = linkedObj;

        dx = linkedObj->posX - obj->posX;
        dy = linkedObj->posY - obj->posY;
        dz = linkedObj->posZ - obj->posZ;
        length = sqrtf(dz * dz + (dx * dx + dy * dy));
        angle = getAngle(dx, dz);
        if (angle > 0x8000)
        {
            angle = (s16)(angle - 0xFFFF);
        }
        if (angle < -0x8000)
        {
            angle += 0xFFFF;
        }
        extra->angle = angle;

        extra->rope =
            DFRope_Create(0x10, lbl_803E4DFC, lbl_803E4DFC, lbl_803E4DFC, dx, dy, dz, length,
                          (&lbl_803DBF50)[*(u8*)(objDef + 0x1b)]);

        extra->minX = obj->posX;
        extra->minZ = obj->posZ;
        extra->maxX = linkedObj->posX;
        extra->maxZ = linkedObj->posZ;
        if (extra->minX > extra->maxX)
        {
            temp = extra->minX;
            extra->minX = extra->maxX;
            extra->maxX = temp;
        }
        if (extra->minZ > extra->maxZ)
        {
            temp = extra->minZ;
            extra->minZ = extra->maxZ;
            extra->maxZ = temp;
        }
        {
            f32 m = lbl_803E4E24;
            extra->minX -= m;
            extra->minZ -= m;
            extra->maxX += m;
            extra->maxZ += m;
        }

        baseX = obj->posX;
        baseY = obj->posY;
        baseZ = obj->posZ;
        linkedX = linkedObj->posX;
        linkedY = linkedObj->posY;
        linkedZ = linkedObj->posZ;
        liftedY = lbl_803E4E28 + baseY;

        normalX = liftedY * (baseZ - linkedZ) +
            (baseY * (linkedZ - baseZ) + (linkedY * (baseZ - baseZ)));
        normalY = baseZ * (baseX - linkedX) +
            (baseZ * (linkedX - baseX) + (linkedZ * (baseX - baseX)));
        normalZ = baseX * (baseY - linkedY) +
            (baseX * (linkedY - liftedY) + (linkedX * (liftedY - baseY)));
        normalLength = sqrtf(normalZ * normalZ + (normalX * normalX + normalY * normalY));
        if (normalLength > lbl_803E4DFC)
        {
            normalX /= normalLength;
            normalY /= normalLength;
            normalZ /= normalLength;
        }
        extra->planeNormalX = normalX;
        extra->planeNormalY = normalY;
        extra->planeNormalZ = normalZ;
        extra->planeDistance = -(baseZ * normalZ + (baseX * normalX + baseY * normalY));
    }

    DFRope_UpdateSimulation((u8*)extra->rope);
}

void dfropenode_init(DFropenodeObject* obj, u8* objDef)
{
    extern void ObjGroup_AddObject(int obj, int group);
    DFropenodeExtra* extra;

    extra = obj->extra;
    if ((&lbl_803DBF58)[*(u8*)(objDef + 0x1b)] == 0)
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~0x80;
    }
    ObjGroup_AddObject((int)obj, 0x17);
    ((GameObject*)obj)->animEventCallback = dfropenode_syncRopeToEndpoints;
    extra->rope = NULL;
    extra->linkedObj = NULL;
    ((GameObject*)obj)->anim.alpha = 0x46;
}

void dfropenode_release(void)
{
    int i;

    for (i = 0; i < 2; i++)
    {
        textureFree((&lbl_803DBF48)[i]);
    }
}

void dfropenode_initialise(void)
{
    int i;

    for (i = 0; i < 2; i++)
    {
        (&lbl_803DBF48)[i] = textureLoadAsset((&lbl_803DBF40)[i]);
    }
}
