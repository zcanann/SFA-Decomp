#include "main/dll/mmshrine/torch1C1.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e5c58;
extern f32 lbl_803DC074;
extern f32 lbl_803E5C28;
extern f32 lbl_803E5C2C;
extern f32 lbl_803E5C30;
extern f32 lbl_803E5C34;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C44;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C4C;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C60;

extern void* lbl_803DDBC4;
extern s16 lbl_80326238[];
extern u8 lbl_80326208[];

void ecsh_shrine_func0B(u8 idx, f32* out1, f32* out2)
{
    int* obj;
    int j;
    if (lbl_803DDBC4 == NULL) return;
    j = lbl_80326238[idx];
    *out1 = *(f32*)((char*)lbl_80326208 + j * 8);
    j = lbl_80326238[idx];
    *out2 = *(f32*)((char*)lbl_80326208 + j * 8 + 4);
    (void)obj;
}

void ecsh_shrine_setScale(s16* out)
{
    int* obj = (int*)lbl_803DDBC4;
    int* state;
    if (obj == NULL) return;
    state = ((GameObject*)obj)->extra;
    *out = *(s16*)((char*)state + 0x20);
}

/*
 * --INFO--
 *
 * Function: FUN_801c5f28
 * EN v1.0 Address: 0x801C5F28
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C5F44
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: ecsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C5F40
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ecsh_shrine_getExtraSize(void)
{
    return 0x38;
}

/*
 * --INFO--
 *
 * Function: ecsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C5F48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ecsh_shrine_getObjectTypeId(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: ecsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C60B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_shrine_hitDetect(void)
{
}

extern void Music_Trigger(int trackId, int restart);
extern void ModelLightStruct_free(void* p);
extern void modelLightStruct_setEnabled(int handle, int flag, f32 v);
extern void objParticleFn_80099d84(int obj, f32 a, int kind, f32 b, int h);
extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E4FC8;

void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void** inner = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        if (*inner != NULL)
        {
            modelLightStruct_setEnabled((int)*inner, 0, lbl_803E4FC8);
        }
        return;
    }
    if (*inner != NULL)
    {
        modelLightStruct_setEnabled((int)*inner, 1, lbl_803E4FC8);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E4FC8);
    objParticleFn_80099d84(obj, lbl_803E4FC8, 7, *(f32*)&lbl_803E4FC8, (int)*inner);
}

void ecsh_shrine_free(int* obj)
{
    int* inner = ((GameObject*)obj)->extra;
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(0x08, 0);
    Music_Trigger(0x0d, 0);
    if (*(void**)inner != NULL)
    {
        ModelLightStruct_free(*(void**)inner);
        *(void**)inner = NULL;
    }
    ObjGroup_RemoveObject((int)obj, 0xb);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
    GameBit_Set(0xa7f, 1);
}
