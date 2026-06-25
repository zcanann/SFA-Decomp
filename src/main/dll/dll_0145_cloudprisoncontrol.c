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
extern int lbl_803AC7D8[];    /* registered-target list, 8B entries */
extern int lbl_803AC878[];    /* deferred-message queue, 12B entries */

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

#pragma scheduling off
#pragma peephole off
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
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4108);
}

void cloudprisoncontrol_init(int x) { ObjMsg_AllocQueue(x, 0xa); }

void cloudprisoncontrol_update(int obj)
{
    int target;
    int data;
    int msg[2];
    int found;
    int i;
    int n;
    int idx;
    int dval;
    int m;
    int* p;

    data = 0;
    if (lbl_803DBE08 != 0)
    {
        lbl_803DDB0C = ((int (*)(int))(*gRomCurveInterface)->slot40)(8);
        lbl_803DBE08 = 0;
    }
    lbl_803DDB08 = 0;
    while (ObjMsg_Pop(obj, msg, &target, &data) != 0)
    {
        m = msg[0];
        switch (m)
        {
        case CPMSG_REGISTER:
            if (((GameObject*)target)->anim.mapEventSlot == ((GameObject*)obj)->anim.mapEventSlot)
            {
                int tgt = target;
                found = 0;
                p = lbl_803AC7D8;
                dval = data;
                n = lbl_803DDB09;
                for (i = 0; i < n; i++)
                {
                    if (*(u32*)p == tgt)
                    {
                        *(s16*)((char*)p + 4) = dval;
                        found = 1;
                    }
                    p += 2;
                }
                if (!found)
                {
                    char* e;
                    i = lbl_803DDB09;
                    e = (char*)lbl_803AC7D8 + i * 8;
                    *(int*)e = tgt;
                    *(u8*)(e + 6) = 0;
                    *(s16*)(e + 4) = data;
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
            n = lbl_803DDB09;
            while (i < n && *(u32*)p != target)
            {
                p += 2;
                i++;
            }
            lbl_803DDB09--;
            n = lbl_803DDB09;
            p = lbl_803AC7D8 + n * 2;
            for (; i < n; i++)
            {
                p[-2] = p[0];
                *(s16*)((char*)p - 4) = *(s16*)((char*)p + 4);
                *(u8*)((char*)p - 2) = *(u8*)((char*)p + 6);
                p -= 2;
            }
            break;
        default:
            idx = lbl_803DDB08 * 0xc;
            *(int*)((char*)lbl_803AC878 + idx + 4) = target;
            *(int*)((char*)lbl_803AC878 + idx) = m;
            *(int*)((char*)lbl_803AC878 + idx + 8) = data;
            lbl_803DDB08++;
            break;
        }
    }
}
