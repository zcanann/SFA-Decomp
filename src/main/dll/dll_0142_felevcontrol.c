#include "main/dll/DB/DBrockfall.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"


extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: paymentkiosk_init
 * EN v1.0 Address: 0x801DF43C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801DF458
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



#pragma scheduling on
#pragma peephole on
static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams* params)
{
    (*gPartfxInterface)->spawnObject((void*)obj, 0x85, params, 1, -1, NULL);
}

static int FEseqobject_findControlObject(void)
{
    int count;
    int i;
    int found;
    int* objects;

    objects = (int*)ObjGroup_GetObjects(3, &count);
    found = 0;
    for (i = 0; i < count; i++)
    {
        int obj = objects[i];
        if (((GameObject*)obj)->anim.seqId == 0xf7)
        {
            found = obj;
            i = count;
        }
    }
    return found;
}

int FEseqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: FUN_801df45c
 * EN v1.0 Address: 0x801DF45C
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x801DF480
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801df784
 * EN v1.0 Address: 0x801DF784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DF7DC
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801df788
 * EN v1.0 Address: 0x801DF788
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801DF918
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */






#pragma scheduling off
#pragma peephole off
void FElevControl_free(void)
{
}

void FElevControl_hitDetect(void)
{
}

void FElevControl_update(void)
{
}

void FElevControl_release(void)
{
}

void FElevControl_initialise(void)
{
}

void dll_144_free(void);





/* 8b "li r3, N; blr" returners. */
int FElevControl_getExtraSize(void) { return 0x0; }
int FElevControl_getObjectTypeId(void) { return 0x0; }
int dll_144_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E56B8;


void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56B8);
}

void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* call(x, N) wrappers. */
void FElevControl_init(int x) { ObjMsg_AllocQueue(x, 0x2); }

/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */
void FEseqobject_init(int obj);

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */

/*
 * Function: dll_144_SeqFn
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */

/*
 * Function: dll_144_init
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */

ObjectDescriptor gFElevControlObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
