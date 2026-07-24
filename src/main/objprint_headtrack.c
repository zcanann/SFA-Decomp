#include "main/game_object.h"
#include "main/objprint_character_api.h"
#include "main/objprint_internal.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

void fn_8003ADC4(GameObject* obj, void* tgt, void* p3, int a, u8 inv, int b)
{
    s16 ang[2];
    s16* found[1];
    void* m[1];

    found[0] = NULL;
    m[0] = (void*)(obj)->anim.modelInstance;
    if (m[0] != NULL)
    {
        int iv[2];
        int n;
        int j;
        iv[0] = (int)found[0];
        iv[1] = (int)found[0];
        n = ((ObjDef*)m[0])->jointCount;
        for (j = 0; j < n; j++)
        {
            int entries = *(int*)&((ObjDef*)m[0])->jointData;
            if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(obj) + iv[0] + 1) != 0xff &&
                (int)*(u8*)(entries + iv[0]) == 0)
            {
                found[0] = (s16*)((char*)(obj)->anim.jointPoseData + iv[1]);
            }
            iv[0] += ((ObjDef*)m[0])->modelCount + 1;
            iv[1] += 0x12;
        }
    }
    if (found[0] != NULL)
    {
        if (tgt == NULL)
        {
            found[0][1] = found[0][1] >> 1;
            found[0][0] = found[0][0] >> 1;
        }
        else
        {
            f32 dx = (obj)->anim.localPosX - ((GameObject*)tgt)->anim.localPosX;
            f32 dy = (obj)->anim.localPosZ - ((GameObject*)tgt)->anim.localPosZ;
            f32 dz = (obj)->anim.localPosY - ((GameObject*)tgt)->anim.localPosY;
            f32 dist = sqrtf(dx * dx + dy * dy);
            ObjJointTrackChannel* channel;
            s16* ap;
            int minB;
            int negA;
            int i;
            f32 prodB;

            ang[0] = (s16)getAngle(dx, dy) - (u16)(obj)->anim.rotX;
            if (ang[0] > 0x8000)
            {
                ang[0] = (s16)(ang[0] - 0xffff);
            }
            if (ang[0] < -0x8000)
            {
                ang[0] = (s16)(ang[0] + 0xffff);
            }
            if (inv != 0)
            {
                ang[0] = (s16)(ang[0] + 0x8000);
            }
            ang[1] = (s16)((s16)getAngle(dist, dz) - 0x3fff);

            a = (s16)(gObjPrintDegToAngle * a);
            channel = p3;
            ap = ang;
            prodB = gObjPrintDegToAngle * b;
            minB = -(s16)(s32)prodB;
            negA = -a;
            for (i = 0; i < 2; i++)
            {
                int v;
                int w;
                *ap -= channel->angle;
                v = *ap;
                if (v < minB)
                {
                    w = minB;
                }
                else
                {
                    if (v > (s16)(s32)prodB)
                    {
                        v = (s32)prodB;
                    }
                    w = (s16)v;
                }
                *ap = (s16)w;
                channel->angle += *ap;
                if (channel->angle > a)
                {
                    channel->angle = a;
                }
                if (channel->angle < negA)
                {
                    channel->angle = negA;
                }
                channel++;
                ap++;
            }
            found[0][1] = *(s16*)((u8*)p3 + 0x14);
            found[0][0] = *(s16*)((u8*)p3 + 0x44);
        }
    }
}
