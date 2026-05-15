#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

#pragma peephole off
#pragma scheduling off

extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int gameBitDecrement(int bit);
extern void ObjHits_DisableObject(void *obj);
extern int ObjTrigger_IsSetById(void *obj, int triggerId);
extern void objRenderFn_80041018(void *obj);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void *Obj_GetPlayerObject(void);
extern int fn_8003B500(void *obj, void *p2, f32 f1);
extern int fn_8003B228(void *obj, void *p2);
extern int characterDoEyeAnims(void *obj, void *p2);
extern void *objCreateLight(void *obj, int arg);
extern void modelLightStruct_setField50(void *light, int value);
extern void modelLightStruct_setColorsA8AC(void *light, int r, int g, int b, int a);
extern void fn_8001DB14(void *light, int value);
extern void lightDistAttenFn_8001dc38(void *light, f32 min, f32 max);
extern void ObjMsg_AllocQueue(void *obj, int count);

extern void *lbl_803DCA54;
extern void *lbl_803DCAA8;
extern void *pDll_expgfx;
extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f64 lbl_803E53A0;
extern f32 lbl_803E5388;
extern f32 lbl_803E538C;
extern f32 lbl_803E5390;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;

void bombplantspore_init(void *obj, void *param2) {
    void *state;
    void *light;
    u32 randAsDouble[2];
    u8 events[8];

    state = *(void **)((u8 *)obj + 0xb8);
    events[0] = 5;
    *(f32 *)((u8 *)state + 0x274) = lbl_803E53F0;
    *(u16 *)((u8 *)obj + 0xb0) |= 0x6000;
    *(f32 *)((u8 *)obj + 0x28) = lbl_803E53F4;
    ObjHits_DisableObject(obj);
    *(s16 *)((u8 *)state + 0x2ac) = (s16)randomGetRange(0, 0xffff);

    randAsDouble[0] = 0x43300000;
    randAsDouble[1] = randomGetRange(0, 1000) ^ 0x80000000;
    *(f32 *)((u8 *)state + 0x280) =
        (*(f64 *)randAsDouble - lbl_803E53A0) / lbl_803E5390;

    (*(void (***)(void *, int, int, int))lbl_803DCAA8)[1](
        (u8 *)state + 0x8, 0, 0x40002, 1);
    (*(void (***)(void *, int, u8 *, u8 *, u8 *))lbl_803DCAA8)[3](
        (u8 *)state + 0x8, 1, lbl_80326D98, &lbl_803DBFC0, events);
    (*(void (***)(void *, void *))lbl_803DCAA8)[8](obj, (u8 *)state + 0x8);
    (*(void (***)(void *, int, int, int, int, int))pDll_expgfx)[2](
        obj, 0x3f1, 0, 4, -1, 0);

    light = objCreateLight(obj, 1);
    if (light != NULL) {
        modelLightStruct_setField50(light, 2);
        modelLightStruct_setColorsA8AC(light, 0xff, 0, 0xff, 0);
        fn_8001DB14(light, 1);
        lightDistAttenFn_8001dc38(light, lbl_803E5388, lbl_803E538C);
    }
    *(void **)((u8 *)state + 0x270) = light;
    ObjMsg_AllocQueue(obj, 2);
    *(s16 *)((u8 *)state + 0x2ae) = (s16)randomGetRange(-0x200, 0x200);
}

void bombplantingspot_update(void *obj) {
    void *pState = *(void **)((u8 *)obj + 0x4c);
    s32 trigBit;

    *(s16 *)obj = (s16)((s8) * ((s8 *)pState + 0x18) << 8);

    trigBit = *(s16 *)((u8 *)pState + 0x20);
    if (trigBit != -1 && GameBit_Get(trigBit) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
        return;
    }

    if (GameBit_Get(0x66c) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x10;
    } else {
        *(u8 *)((u8 *)obj + 0xaf) &= ~0x10;
    }

    if (ObjTrigger_IsSetById(obj, 0x66c) != 0) {
        gameBitDecrement(0x66c);
        GameBit_Set(*(s16 *)((u8 *)pState + 0x1e), 1);
        (*(void (***)(int, void *, int))lbl_803DCA54)[0x12](1, obj, -1);
    } else if ((*(u8 *)((u8 *)obj + 0xaf) & 0x4) != 0 && GameBit_Get(0x196) == 0) {
        (*(void (***)(int, void *, int))lbl_803DCA54)[0x12](0, obj, -1);
        GameBit_Set(0x196, 1);
    }

    if (GameBit_Get(*(s16 *)((u8 *)pState + 0x1e)) == 0) {
        *(u8 *)((u8 *)obj + 0xaf) &= ~0x8;
        objRenderFn_80041018(obj);
    } else {
        *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
    }
}

void bombplantingspot_init(void *obj, void *param2) {
    *(u16 *)((u8 *)obj + 0xb0) |= 0x4000;
    *(s16 *)obj = (s16)((s8) * ((s8 *)param2 + 0x18) << 8);
}

int fn_801D4198(void *obj, void *unused, void *p5) {
    void *pState = *(void **)((u8 *)obj + 0xb8);
    int i;
    u8 b2;

    if ((*(u8 *)((u8 *)pState + 0x2) & 0x20) == 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        *(u8 *)((u8 *)pState + 0x2) &= ~0x10;
        *(u8 *)((u8 *)pState + 0x2) |= 0x20;
    }

    for (i = 0; i < *(u8 *)((u8 *)p5 + 0x8b); i++) {
        switch (*(u8 *)((int)p5 + i + 0x81)) {
            case 0:
                *(u8 *)((u8 *)pState + 0x2) |= 0x8;
                break;
            case 1:
                *(u8 *)((u8 *)pState + 0x2) &= ~0x8;
                break;
            case 2:
                *(u8 *)((u8 *)pState + 0x2) |= 0x2;
                break;
            case 3:
                *(u8 *)((u8 *)pState + 0x2) &= ~0x2;
                *(s16 *)((u8 *)p5 + 0x6e) |= 0x8;
                *(s16 *)((u8 *)p5 + 0x6e) |= 0x40;
                break;
        }
    }

    b2 = *(u8 *)((u8 *)pState + 0x2);
    if ((b2 & 0x2) != 0) {
        if ((b2 & 0x4) == 0) {
            void *player;
            *(s16 *)((u8 *)p5 + 0x6e) &= ~0x8;
            player = Obj_GetPlayerObject();
            *(u8 *)((u8 *)pState + 0x8) = 1;
            *(f32 *)((u8 *)pState + 0xc) = *(f32 *)((u8 *)player + 0xc);
            *(f32 *)((u8 *)pState + 0x10) = *(f32 *)((u8 *)player + 0x10);
            *(f32 *)((u8 *)pState + 0x14) = *(f32 *)((u8 *)player + 0x14);
            fn_8003B500(obj, (u8 *)pState + 0x8, lbl_803E53F8);
        }
        *(s16 *)((u8 *)p5 + 0x6e) &= ~0x40;
        if ((*(u8 *)((u8 *)pState + 0x2) & 0x8) != 0) {
            fn_8003B228(obj, (u8 *)pState + 0x8);
        } else {
            characterDoEyeAnims(obj, (u8 *)pState + 0x8);
        }
    }
    return 0;
}
