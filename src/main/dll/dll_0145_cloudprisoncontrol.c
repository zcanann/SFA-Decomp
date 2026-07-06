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
#include "main/dll/rom_curve_interface.h"
#include "main/dll/VF/vf_shared.h"
extern int ObjMsg_Pop();
extern void ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue();
extern s8 lbl_803DBE08;       /* curve-system one-shot init flag */
extern f32 lbl_803E4108;      /* render scale */
extern s8 lbl_803DDB08;       /* deferred-message queue count */
extern s8 lbl_803DDB09;       /* registered-target list count */
extern int lbl_803DDB0C;      /* cached rom-curve handle */

/* Registered prison-member entry (list keyed by the controller's map-event slot). */
typedef struct CPTargetEntry
{
    u32 obj;    /* member GameObject* (compared/stored as a word) */
    s16 value;  /* per-member value supplied with the register message */
    u8 flags;   /* cleared on registration */
    u8 pad;
} CPTargetEntry;

/* Deferred message queued for another handler (12B entries). */
typedef struct CPDeferredMsg
{
    int msgId;
    u32 sender; /* sending GameObject* */
    int data;
} CPDeferredMsg;

CPTargetEntry lbl_803AC7D8[20];  /* registered-target list */
int lbl_803AC878[0x22];          /* deferred-message queue storage */

/* ObjMsg ids exchanged with prison members */
enum
{
    CPMSG_ACK = 0xf0003,        /* controller -> member: registered */
    CPMSG_REGISTER = 0xf0004,   /* member -> controller: register/update */
    CPMSG_IGNORED_5 = 0xf0005,
    CPMSG_IGNORED_6 = 0xf0006,
    CPMSG_IGNORED_7 = 0xf0007,
    CPMSG_UNREGISTER = 0xf0008  /* member -> controller: remove */
};

void cloudprisoncontrol_free(void)
{
}

void cloudprisoncontrol_hitDetect(void)
{
}

void cloudprisoncontrol_release(void)
{
}

int cloudprisoncontrol_getExtraSize(void) { return 0x0; }
int cloudprisoncontrol_getObjectTypeId(void) { return 0x0; }

void cloudprisoncontrol_initialise(void) { lbl_803DBE08 = 1; }

void cloudprisoncontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4108);
}

void cloudprisoncontrol_init(int x) { ObjMsg_AllocQueue(x, 0xa); }

void cloudprisoncontrol_update(int obj)
{
    int target;
    int data;
    int msg[2];
    int i;
    int count;
    int idx;
    int dval;
    int msgId;
    CPTargetEntry* p;
    int found;

    data = 0;
    if (lbl_803DBE08 != 0)
    {
        lbl_803DDB0C = ((int (*)(int))(*gRomCurveInterface)->slot40)(8);
        lbl_803DBE08 = 0;
    }
    lbl_803DDB08 = 0;
    while (ObjMsg_Pop(obj, msg, &target, &data) != 0)
    {
        msgId = msg[0];
        switch (msgId)
        {
        case CPMSG_REGISTER:
            if (((GameObject*)target)->anim.mapEventSlot == ((GameObject*)obj)->anim.mapEventSlot)
            {
                int tgt = target;
                found = 0;
                p = lbl_803AC7D8;
                dval = data;
                count = lbl_803DDB09;
                for (i = 0; i < count; i++)
                {
                    if (p->obj == tgt)
                    {
                        p->value = dval;
                        found = 1;
                    }
                    p++;
                }
                if (!found)
                {
                    CPTargetEntry* e;
                    i = lbl_803DDB09;
                    e = &lbl_803AC7D8[i];
                    e->obj = tgt;
                    e->flags = 0;
                    e->value = data;
                    lbl_803DDB09++;
                }
                ObjMsg_SendToObject(target, CPMSG_ACK, obj, 0);
            }
            break;
        case CPMSG_IGNORED_5:
        case CPMSG_IGNORED_6:
        case CPMSG_IGNORED_7:
            break;
        case CPMSG_UNREGISTER:
            i = 0;
            p = lbl_803AC7D8;
            count = lbl_803DDB09;
            while (i < count && p->obj != (u32)target)
            {
                p++;
                i++;
            }
            lbl_803DDB09--;
            count = lbl_803DDB09;
            p = &lbl_803AC7D8[count];
            for (; i < count; i++)
            {
                p[-1].obj = p[0].obj;
                p[-1].value = p[0].value;
                p[-1].flags = p[0].flags;
                p--;
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
