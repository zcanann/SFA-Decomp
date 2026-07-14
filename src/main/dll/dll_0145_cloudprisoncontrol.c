/*
 * cloudprisoncontrol (DLL 0x145) - the per-map controller object for the
 * cloud-prison set piece. It owns no per-instance state (getExtraSize
 * returns 0) and acts purely as a message hub: on its first update it
 * caches a rom-curve handle (slot 40, curve id 8) into lbl_803DDB0C, then
 * drains its ObjMsg queue every frame.
 *
 * Two global tables, keyed by the controller's own anim.mapEventSlot,
 * track the prison members:
 *   - lbl_803AC7D8: registered-target list (8B entries, count lbl_803DDB09)
 *   - lbl_803AC878: deferred-message queue (12B entries, count lbl_803DDB08)
 *
 * Messages handled (objmsg ids 0xF000x):
 *   0xF0004 register/update a target (replies 0xF0003 to the sender),
 *   0xF0005..0xF0007 ignored, 0xF0008 unregister a target (compacts the
 *   list), any other id is appended to the deferred-message queue.
 */
#include "main/game_object.h"
#include "main/obj_message.h"
#include "main/dll/rom_curve_interface.h"
#include "main/object_render_legacy.h"

/* Registered prison-member entry (list keyed by the controller's map-event slot). */
typedef struct CPTargetEntry
{
    u32 obj;   /* member GameObject* (compared/stored as a word) */
    s16 value; /* per-member value supplied with the register message */
    u8 flags;  /* cleared on registration */
    u8 pad;
} CPTargetEntry;

/* Deferred message queued for another handler (12B entries). */
typedef struct CPDeferredMsg
{
    int msgId;
    u32 sender; /* sending GameObject* */
    int data;
} CPDeferredMsg;

/* ObjMsg ids exchanged with prison members */
enum
{
    CPMSG_ACK = 0xf0003,      /* controller -> member: registered */
    CPMSG_REGISTER = 0xf0004, /* member -> controller: register/update */
    CPMSG_IGNORED_5 = 0xf0005,
    CPMSG_IGNORED_6 = 0xf0006,
    CPMSG_IGNORED_7 = 0xf0007,
    CPMSG_UNREGISTER = 0xf0008 /* member -> controller: remove */
};

extern s8 lbl_803DBE08;  /* curve-system one-shot init flag */
extern f32 lbl_803E4108; /* render scale */
extern s8 lbl_803DDB08;  /* deferred-message queue count */
extern s8 lbl_803DDB09;  /* registered-target list count */
extern int lbl_803DDB0C; /* cached rom-curve handle */


CPTargetEntry lbl_803AC7D8[20]; /* registered-target list */
int lbl_803AC878[0x22];         /* deferred-message queue storage */

void CloudPrisonControl_free(void)
{
}

void CloudPrisonControl_hitDetect(void)
{
}

void CloudPrisonControl_release(void)
{
}

int CloudPrisonControl_getExtraSize(void)
{
    return 0x0;
}
int CloudPrisonControl_getObjectTypeId(void)
{
    return 0x0;
}

void CloudPrisonControl_initialise(void)
{
    lbl_803DBE08 = 1;
}

void CloudPrisonControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4108);
}

void CloudPrisonControl_init(GameObject* obj)
{
    ObjMsg_AllocQueue(obj, 0xa);
}

void CloudPrisonControl_update(GameObject* obj)
{
    int target;
    int data;
    int msg[2];
    int i;
    int count;
    int idx;
    int dval;
    int msgId;
    CPTargetEntry* p[1];
    int found;

    data = 0;
    if (lbl_803DBE08 != 0)
    {
        lbl_803DDB0C = ((int (*)(int))(*gRomCurveInterface)->slot40)(8);
        lbl_803DBE08 = 0;
    }
    lbl_803DDB08 = 0;
    while (ObjMsg_Pop(obj, (u32*)msg, (u32*)&target, (u32*)&data) != 0)
    {
        msgId = msg[0];
        switch (msgId)
        {
        case CPMSG_REGISTER:
            if (((GameObject*)target)->anim.mapEventSlot == (obj)->anim.mapEventSlot)
            {
                found = 0;
                p[0] = lbl_803AC7D8;
                dval = data;
                count = lbl_803DDB09;
                for (i = 0; i < count; i++)
                {
                    if (p[0]->obj == (u32)target)
                    {
                        p[0]->value = dval;
                        found = 1;
                    }
                    p[0]++;
                }
                if (!found)
                {
                    lbl_803AC7D8[lbl_803DDB09].obj = target;
                    lbl_803AC7D8[lbl_803DDB09].flags = 0;
                    lbl_803AC7D8[lbl_803DDB09++].value = data;
                }
                ObjMsg_SendToObject((void*)target, CPMSG_ACK, obj, 0);
            }
            break;
        case CPMSG_IGNORED_5:
        case CPMSG_IGNORED_6:
        case CPMSG_IGNORED_7:
            break;
        case CPMSG_UNREGISTER:
            i = 0;
            p[0] = lbl_803AC7D8;
            count = lbl_803DDB09;
            while (i < count && p[0]->obj != (u32)target)
            {
                p[0]++;
                i++;
            }
            lbl_803DDB09--;
            count = lbl_803DDB09;
            p[0] = &lbl_803AC7D8[count];
            for (; i < count; i++)
            {
                p[0][-1].obj = p[0][0].obj;
                p[0][-1].value = p[0][0].value;
                p[0][-1].flags = p[0][0].flags;
                p[0]--;
            }
            break;
        default:
            idx = lbl_803DDB08 * 0xc;
            ((CPDeferredMsg*)((char*)lbl_803AC878 + idx))->sender = target;
            ((CPDeferredMsg*)((char*)lbl_803AC878 + idx))->msgId = msgId;
            ((CPDeferredMsg*)((char*)lbl_803AC878 + idx))->data = data;
            lbl_803DDB08++;
            break;
        }
    }
}

u32 gCloudPrisonControlObjDescriptor[30] = {0x00000000,
                                            0x00000000,
                                            0x00000000,
                                            0x00090000,
                                            (u32)CloudPrisonControl_initialise,
                                            (u32)CloudPrisonControl_release,
                                            0x00000000,
                                            (u32)CloudPrisonControl_init,
                                            (u32)CloudPrisonControl_update,
                                            (u32)CloudPrisonControl_hitDetect,
                                            (u32)CloudPrisonControl_render,
                                            (u32)CloudPrisonControl_free,
                                            (u32)CloudPrisonControl_getObjectTypeId,
                                            (u32)CloudPrisonControl_getExtraSize,
                                            0x00000000,
                                            0x00000000,
                                            0x00000000,
                                            0x00000000,
                                            0x41b00000,
                                            0x00000000,
                                            0x00000000,
                                            0x41c00000,
                                            0x41c80000,
                                            0x00000000,
                                            0x41f00000,
                                            0xc1c80000,
                                            0x00000000,
                                            0x41b80000,
                                            0x41a00000,
                                            0x41800000};
u32 lbl_80322798[3] = {0x00000001, 0x00000006, 0x0000000d};
u32 lbl_803227A4[3] = {0x0000000f, 0x00000006, 0xffffffff};
u32 lbl_803227B0[3] = {0x00000005, 0xffffffff, 0xffffffff};
u32 lbl_803227BC[3] = {0x00000002, 0xffffffff, 0xffffffff};
u32 lbl_803227C8[3] = {0x00000008, 0x00000006, 0xffffffff};
u32 lbl_803227D4[3] = {0x0000000c, 0xffffffff, 0xffffffff};
u32 lbl_803227E0[3] = {0x0000000e, 0xffffffff, 0xffffffff};
u32 lbl_803227EC[3] = {0x0000000e, 0x00000006, 0xffffffff};
u32 lbl_803227F8[3] = {0x0000000e, 0x00000006, 0xffffffff};
u32 lbl_80322804[3] = {0x00000009, 0x00000006, 0xffffffff};
u32 lbl_80322810[3] = {0x00000005, 0xffffffff, 0xffffffff};
u32 lbl_8032281C[3] = {0x0000000b, 0xffffffff, 0xffffffff};
u32 lbl_80322828[3] = {0x0000000a, 0xffffffff, 0xffffffff};
u32 lbl_80322834[3] = {0x0000000e, 0x00000006, 0x00000010};
u32 lbl_80322840[3] = {0xffffffff, 0xffffffff, 0xffffffff};
