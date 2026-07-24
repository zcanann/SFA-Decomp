#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/debug.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/obj_contact.h"
#include "main/obj_group.h"
#include "main/objseq.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/pi_dolphin.h"
#include "main/dll/dll_0004_dummy04.h"
#include "string.h"

extern u8** gObjFileBufferTable;
extern u8* gObjFileRefCount;
extern GameObject** gObjList;
extern int gObjCount;
extern char sObjFreeObjdefError[];

/* ObjGroup ids (registered/unregistered in Obj_SetupObject / Obj_FreeObject) */
#define OBJECT_OBJGROUP_HITBOX 6 /* joined when modelInstance flags & 0x40 (SKIP_RESET_UPDATE) */
#define OBJECT_OBJGROUP_GROUP8 8 /* joined when modelInstance->group8RegistrationCount > 0 */

ObjPlacement* Obj_AllocObjectSetup(int size, int type)
{
    ObjPlacement* p = mmAlloc(size, 0xe, 0);
    memset(p, 0, size);
    p->mapId = -1;
    p->color[2] = 0x64;
    p->color[3] = 0x96;
    p->color[0] = 8;
    p->color[1] = 4;
    p->objectId = type;
    p->size = size;
    return p;
}
void objFreeObjDef(u8* obj, int flag)
{
    int defs[40];
    void (*fp)(u8*, int);
    void (*cb)(u8*);
    BoneParticleEffectSpawnFn cb2;
    int i;
    int j;
    int n;
    int count;
    u8* otherObj;
    int* bp;
    void* curTex;
    void* tex;
    void* shadowRenderResource;
    int modelCount;
    int group;

    if (*(u8*)&((GameObject*)obj)->contactRefCount != 0)
    {
        ObjContact_RemoveObjectCallbacks((GameObject*)obj);
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0:
    case 0x1f:
        fn_802B4DE0((GameObject*)obj, flag);
        break;
    default:
        if (((GameObject*)obj)->anim.dll != NULL)
        {
            fp = *(void (**)(u8*, int))((char*)*((GameObject*)obj)->anim.dll + 0x14);
            if (fp != NULL)
            {
                fp(obj, flag);
            }
            Resource_Release(((GameObject*)obj)->anim.dll);
            *(int*)&((GameObject*)obj)->anim.dll = 0;
        }
        break;
    }
    gTitleMenuControlInterface->vtable->func15(obj);
    (*gExpgfxInterface)->freeOwner3((u32)obj);
    if (((ObjAnimComponent*)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE)
    {
        ObjGroup_RemoveObject((u32)obj, OBJECT_OBJGROUP_HITBOX);
        if (flag == 0)
        {
            count = 0;
            for (i = 0; i < gObjCount; i++)
            {
                otherObj = (u8*)gObjList[i];
                if (*(int*)&((GameObject*)otherObj)->anim.parent == (int)obj)
                {
                    *(int*)&((GameObject*)otherObj)->anim.parent = 0;
                    if (*(void**)&((GameObject*)otherObj)->anim.placementData != NULL)
                    {
                        defs[count++] = (int)otherObj;
                    }
                }
            }
            for (n = 0; n < count; n++)
            {
                Obj_FreeObject((GameObject*)defs[n]);
            }
            mapUnloadRomListPage(*(u8*)(obj + 0x34));
        }
    }
    if (flag == 0 && ((GameObject*)obj)->anim.classId == 0x10)
    {
        for (i = 0; i < gObjCount; i++)
        {
            otherObj = (u8*)gObjList[i];
            if (*(int*)&((GameObject*)otherObj)->pendingParentObj == (int)obj)
            {
                *(int*)&((GameObject*)otherObj)->pendingParentObj = 0;
            }
        }
    }
    for (j = 0; j < gObjCount; j++)
    {
        if (gObjList[j]->anim.classId == 0x10)
        {
            bp = (int*)gObjList[j]->extra;
            if (*(u8**)bp == obj)
            {
                *bp = 0;
                *((u8*)bp + 0x8f) = 1;
            }
        }
    }
    if (((ObjAnimComponent*)obj)->modelInstance->group8RegistrationCount > 0)
    {
        ObjGroup_RemoveObject((u32)obj, OBJECT_OBJGROUP_GROUP8);
    }
    if (((ObjAnimComponent*)obj)->modelState != NULL)
    {
        if (((ObjAnimComponent*)obj)->modelInstance->shadowType == OBJ_SHADOW_TYPE_BIG_BOX)
        {
            shadowVolumesSetDirty(1);
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowTexture != NULL)
        {
            curTex = (void*)getNewShadowSmallDiskTexture();
            tex = ((ObjAnimComponent*)obj)->modelState->shadowTexture;
            if (tex != curTex)
            {
                if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
                {
                    mm_free(tex);
                }
                else
                {
                    textureFree((Texture*)(tex));
                }
            }
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer != NULL)
        {
            mm_free(((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer);
        }
        shadowRenderResource = ((ObjAnimComponent*)obj)->modelState->shadowRenderResource;
        if (shadowRenderResource != NULL && shadowRenderResource != (void*)-1)
        {
            mm_free(shadowRenderResource);
        }
    }
    if (*(void**)&((GameObject*)obj)->unkDC != NULL)
    {
        mm_free(((GameObject*)obj)->unkDC);
        *(int*)&((GameObject*)obj)->unkDC = 0;
    }
    modelCount = ((ObjAnimComponent*)obj)->modelInstance->modelCount;
    for (j = 0; j < modelCount; j++)
    {
        if ((int)((ObjAnimComponent*)obj)->banks[j] != 0)
        {
            ObjModel_Release((u8*)((ObjAnimComponent*)obj)->banks[j]);
        }
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN)
    {
        ((GameObject*)obj)->colorFadeFrames = 0;
        ((GameObject*)obj)->colorFadeFlags = ((GameObject*)obj)->colorFadeFlags & ~OBJ_COLOR_FADE_FLAG_FROZEN;
        ((GameObject*)obj)->fadeCounter = 0;
        ObjModel_ClearRenderAttachment((ObjModel*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex]);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fb, NULL, 0x50, NULL);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fc, NULL, 0x32, NULL);
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE)
    {
        Obj_ClearModelColorFadeRecursive((GameObject*)obj);
    }
    group = ObjGroup_GetObjectGroup((u32)obj);
    if (group != 0)
    {
        ObjGroup_RemoveObject((u32)obj, group - 1);
    }
    {
        s16 type;
        u8* refCounts;

        type = ((GameObject*)obj)->anim.defId;
        refCounts = gObjFileRefCount;
        if (refCounts[type] == 0)
        {
            debugPrintf(sObjFreeObjdefError);
        }
        else
        {
            refCounts[type]--;
            if (gObjFileRefCount[type] == 0)
            {
                otherObj = gObjFileBufferTable[type];
                if (*(void**)&((GameObject*)otherObj)->anim.parent != NULL)
                {
                    mm_free(((GameObject*)otherObj)->anim.parent);
                }
                if (*(void**)(otherObj + 0x34) != NULL)
                {
                    mm_free(*(void**)(otherObj + 0x34));
                }
                mm_free(otherObj);
            }
        }
    }
    if (((GameObject*)obj)->seqIndex > -1)
    {
        if (flag == 0)
        {
            (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
        }
        ((GameObject*)obj)->seqIndex = 0xffff;
    }
    if ((*(s16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) &&
        *(void**)&((GameObject*)obj)->anim.placementData != NULL)
    {
        mm_free(((GameObject*)obj)->anim.placementData);
    }
    mm_free(obj);
}
