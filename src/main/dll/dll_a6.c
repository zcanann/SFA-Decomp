#include "main/dll/dll_A6.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern f32 lbl_803E1628;
extern f32 lbl_803E162C;

extern void objRenderFn_8003b8f4(u8* reticle, undefined4 a, undefined4 b, undefined4 c,
                                 undefined4 d, f32 f);

void camcontrol_updateTargetReticle(CamcontrolTargetObject* fallbackTarget, int unused2,
                                    undefined4 arg3, undefined4 arg4,
                                    undefined4 arg5, undefined4 arg6)
{
    int savedReticleState;
    u8 savedReticleAlpha;
    u8* reticle;
    u8* target;
    u8* otherTbl;
    u8* slot;
    u8* paletteBase;
    u8 idx;
    int mode;
    int paletteIdx;
    u16* flagsObj;

    reticle = (u8*)gCamcontrolTargetReticle;
    target = (u8*)fallbackTarget;
    if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0)
    {
        target = (u8*)CAMCONTROL_CAMERA->targetReticleOverride;
        savedReticleState = gCamcontrolTargetState;
        gCamcontrolTargetState = 3;
        savedReticleAlpha = ((GameObject*)reticle)->anim.alpha;
        ((GameObject*)reticle)->anim.alpha = 0xFF;
    }

    if (target != NULL)
    {
        if (*(u32*)(target + 0x74) == 0) goto end;

        idx = ((GameObject*)target)->unkE4;
        slot = (u8*)*(u32*)(target + 0x74) + idx * 0x18;
        otherTbl = (u8*)*(u32*)(target + 0x78);
        otherTbl = otherTbl + idx * 5;

        switch (*(otherTbl + 4) & 0xF)
        {
        case 1:
            mode = 0;
            break;
        case 4:
        case 9:
            mode = 2;
            break;
        default:
            mode = 1;
            break;
        }

        paletteIdx = (int)((GameObject*)target)->paletteIndex;
        if (paletteIdx >= 4) paletteIdx = 0;
        paletteBase = (u8*)*(u32*)&((GameObject*)target)->anim.modelInstance;
        paletteBase = paletteBase + paletteIdx * 2;
        gCamcontrolTargetHelpTextId = *(s16*)(paletteBase + 0x7C);

        ((GameObject*)reticle)->anim.worldPosX = *(f32*)(slot + 0x0);
        ((GameObject*)reticle)->anim.worldPosY = *(f32*)(slot + 0x4);
        ((GameObject*)reticle)->anim.worldPosZ = *(f32*)(slot + 0x8);
        ((GameObject*)reticle)->anim.bankIndex = mode;

        *(u32*)&((GameObject*)reticle)->anim.parent = *(u32*)&((GameObject*)target)->anim.parent;
        if (*(u32*)&((GameObject*)reticle)->anim.parent != 0)
        {
            Obj_TransformWorldPointToLocal(((GameObject*)reticle)->anim.worldPosX,
                                           ((GameObject*)reticle)->anim.worldPosY,
                                           ((GameObject*)reticle)->anim.worldPosZ,
                                           (f32*)(reticle + 0xC), (f32*)(reticle + 0x10),
                                           (f32*)(reticle + 0x14),
                                           *(u32*)&((GameObject*)reticle)->anim.parent);
        }
        else
        {
            ((GameObject*)reticle)->anim.localPosX = ((GameObject*)reticle)->anim.worldPosX;
            ((GameObject*)reticle)->anim.localPosY = ((GameObject*)reticle)->anim.worldPosY;
            ((GameObject*)reticle)->anim.localPosZ = ((GameObject*)reticle)->anim.worldPosZ;
        }
        ((GameObject*)reticle)->anim.rotY = 0;
        ((GameObject*)reticle)->anim.rotZ = 0;
        ((GameObject*)reticle)->anim.rootMotionScale = lbl_803E1628;
        reticle[0x37] = ((GameObject*)reticle)->anim.alpha;
        objRenderFn_8003b8f4(reticle, arg3, arg4, arg5, arg6, lbl_803E162C);
    }
    else
    {
        *(u32*)&((GameObject*)reticle)->anim.parent = 0;
    }

    flagsObj = *(u16**)((u8*)*(u32*)&((GameObject*)reticle)->anim.banks + (s8)reticle[0xAD] * 4);
    *(u16*)((u8*)flagsObj + 0x18) = (u16)(*(u16*)((u8*)flagsObj + 0x18) & ~8);

    if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0)
    {
        gCamcontrolTargetState = (s8)savedReticleState;
        ((GameObject*)reticle)->anim.alpha = savedReticleAlpha;
    }
end:
    ;
}
