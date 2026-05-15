#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

#pragma peephole off
#pragma scheduling off

extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int gameBitDecrement(int bit);
extern int gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(void *obj, int id);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern void *ObjHits_GetPriorityHitWithPosition(void *obj, int *hit, void *pos, int flags);
extern void *ObjHits_GetPriorityHit(void *obj, void *pos, int p3, int p4);
extern int ObjMsg_Pop(void *obj, u32 *outMessage, u32 *outSender, u32 *outParam);
extern int ObjTrigger_IsSetById(void *obj, int triggerId);
extern void objRenderFn_80041018(void *obj);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void *Obj_GetPlayerObject(void);
extern void Obj_FreeObject(void *obj);
extern void objMove(f32 x, f32 y, f32 z, void *obj);
extern int fn_8003B500(void *obj, void *p2, f32 f1);
extern int fn_8003B228(void *obj, void *p2);
extern int characterDoEyeAnims(void *obj, void *p2);
extern void *objCreateLight(void *obj, int arg);
extern void lightFn_8001db6c(f32 f1, void *light, int arg);
extern void modelLightStruct_setField50(void *light, int value);
extern void modelLightStruct_setColorsA8AC(void *light, int r, int g, int b, int a);
extern void fn_8001DB14(void *light, int value);
extern void lightDistAttenFn_8001dc38(void *light, f32 min, f32 max);
extern void ObjMsg_AllocQueue(void *obj, int count);
extern void ObjMsg_SendToObject(void *dst, int msg, void *src, void *payload);
extern void objFn_800972dc(f32 f1, f32 f2, void *obj, int p4, int p5, int p6, int p7, int p8, int p9);
extern int randomGetRange(int min, int max);
extern void fn_801D33D4(void *obj, void *state);
extern void fn_801D359C(void *obj, void *state);

extern void *lbl_803DCA54;
extern void *lbl_803DCA78;
extern void *lbl_803DCAA8;
extern void *pDll_expgfx;
extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f64 lbl_803E53A0;
extern f32 lbl_803E5388;
extern f32 lbl_803E538C;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B8;
extern f32 lbl_803E53BC;
extern f32 lbl_803E53C0;
extern f32 lbl_803E53C4;
extern f32 lbl_803E53C8;
extern f64 lbl_803E53D0;
extern f64 lbl_803E53D8;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53E8;
extern f32 lbl_803E53EC;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;

void bombplantspore_update(void *obj) {
    void *state;
    s32 particleAlpha;
    s16 hitId;
    void *hitObj;
    void *playerObj;
    u32 poppedMessage;
    u32 poppedSender;
    undefined hitPosition[4];
    u32 detonateMessage;
    int i;

    state = *(void **)((u8 *)obj + 0xb8);
    if ((*(u8 *)((u8 *)state + 0x2b0) >> 6 & 1) != 0) {
        detonateMessage = 0x7000b;
        while (ObjMsg_Pop(obj, &poppedMessage, &poppedSender, NULL) != 0) {
            if (poppedMessage == detonateMessage) {
                gameBitIncrement(0x66c);
                Sfx_PlayFromObject(obj, 0xa7);
                (*(void (***)(void *))lbl_803DCA78)[5](obj);
                for (i = 0; i < 10; i++) {
                    objFn_800972dc(lbl_803E53B0, lbl_803E53B8, obj, 5, 7, 1, 0x3c, 0, 0);
                    (*(void (***)(void *, int, int, int, int, int))pDll_expgfx)[2](
                        obj, 0x3f3, 0, 4, -1, 0);
                }
                lightFn_8001db6c(lbl_803E53AC, *(void **)((u8 *)state + 0x270), 0);
                *(f32 *)((u8 *)state + 0x2a4) = lbl_803E53BC;
                *(s16 *)((u8 *)obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
                *(u8 *)((u8 *)state + 0x2b0) &= 0xbf;
            }
        }
        if ((*(u8 *)((u8 *)state + 0x2b0) >> 6 & 1) != 0) {
            return;
        }
    }

    if (*(f32 *)((u8 *)state + 0x2a4) != lbl_803E5394) {
        *(s16 *)obj += (u16)framesThisStep * 0x40;
        *(f32 *)((u8 *)state + 0x2a4) -= timeDelta;
        if (*(f32 *)((u8 *)state + 0x2a4) <= lbl_803E5394) {
            Obj_FreeObject(obj);
        }
        return;
    }

        if (*(f32 *)((u8 *)state + 0x274) < lbl_803E53C0) {
            particleAlpha = (s32)-(lbl_803E53C8 * *(f32 *)((u8 *)state + 0x274) - lbl_803E53C4);
            objFn_800972dc(lbl_803E53B0,
                           (f32)(lbl_803E53D8 *
                                     (double)(lbl_803E53C0 - *(f32 *)((u8 *)state + 0x274)) +
                                 lbl_803E53D0),
                           obj, 5, 7, 1, particleAlpha & 0xff, 0, 0);
        }
        ObjHits_GetPriorityHit(obj, hitPosition, 0, 0);
        hitObj = **(void ***)((u8 *)obj + 0x54);
        if ((*(u8 *)((u8 *)state + 0x2b0) & 0x80) == 0) {
            *(f32 *)((u8 *)state + 0x284) -= timeDelta;
            if (*(f32 *)((u8 *)state + 0x284) < lbl_803E5394) {
                *(f32 *)((u8 *)state + 0x284) = lbl_803E5394;
            }
            *(f32 *)((u8 *)state + 0x2a0) -= timeDelta;
            if (*(f32 *)((u8 *)state + 0x2a0) < lbl_803E5394) {
                *(f32 *)((u8 *)state + 0x2a0) = lbl_803E5394;
            }
            *(s16 *)obj += *(u16 *)((u8 *)state + 0x2ae);
            *(f32 *)((u8 *)obj + 0x28) = lbl_803E53E0 * timeDelta + *(f32 *)((u8 *)obj + 0x28);
            if (lbl_803E53E4 > *(f32 *)((u8 *)obj + 0x28)) {
                *(f32 *)((u8 *)obj + 0x28) = lbl_803E53E4;
            }
            if (*(f32 *)((u8 *)obj + 0x28) > lbl_803E5394) {
                *(f32 *)((u8 *)obj + 0x28) *= lbl_803E53E8;
            }
            if (*(f32 *)((u8 *)obj + 0x28) < lbl_803E5394) {
                ObjHits_EnableObject(obj);
            }
            fn_801D359C(obj, state);
            if (randomGetRange(0, 100) < 5 &&
                *(f32 *)((u8 *)state + 0x284) <= lbl_803E5394) {
                fn_801D33D4(obj, state);
            }
            *(f32 *)((u8 *)state + 0x298) -= timeDelta;
            if (*(f32 *)((u8 *)state + 0x298) <= lbl_803E5394) {
                *(f32 *)((u8 *)state + 0x290) *= lbl_803E53E8;
                *(f32 *)((u8 *)state + 0x294) *= lbl_803E53E8;
                *(f32 *)((u8 *)state + 0x298) = lbl_803E5394;
            } else {
                *(f32 *)((u8 *)state + 0x27c) =
                    lbl_803E53EC *
                        (*(f32 *)((u8 *)state + 0x29c) - *(f32 *)((u8 *)state + 0x27c)) *
                        timeDelta +
                    *(f32 *)((u8 *)state + 0x27c);
            }
            *(f32 *)((u8 *)obj + 0x24) =
                *(f32 *)((u8 *)state + 0x290) * *(f32 *)((u8 *)state + 0x27c) +
                *(f32 *)((u8 *)state + 0x288);
            *(f32 *)((u8 *)obj + 0x2c) =
                *(f32 *)((u8 *)state + 0x294) * *(f32 *)((u8 *)state + 0x27c) +
                *(f32 *)((u8 *)state + 0x28c);
            objMove(*(f32 *)((u8 *)obj + 0x24) * timeDelta,
                    *(f32 *)((u8 *)obj + 0x28) * timeDelta,
                    *(f32 *)((u8 *)obj + 0x2c) * timeDelta, obj);
            (*(void (***)(f32, void *, void *))lbl_803DCAA8)[4](timeDelta, obj, (u8 *)state + 4);
            (*(void (***)(void *, void *))lbl_803DCAA8)[5](obj, (u8 *)state + 4);
            (*(void (***)(f32, void *, void *))lbl_803DCAA8)[6](timeDelta, obj, (u8 *)state + 4);
            if (hitObj != NULL &&
                (hitId = *(s16 *)((u8 *)hitObj + 0x46), hitId != 0x36d) &&
                hitId != 0x198 && hitId != 0x63c) {
                Sfx_PlayFromObject(obj, 0x59);
                *(u8 *)((u8 *)state + 0x2b0) = *(u8 *)((u8 *)state + 0x2b0) & 0x7f | 0x80;
                if (lbl_803E53C0 < *(f32 *)((u8 *)state + 0x274)) {
                    *(f32 *)((u8 *)state + 0x274) = lbl_803E53C0;
                }
            }
            if ((*(u8 *)((u8 *)state + 0x268) & 0x11) != 0) {
                *(u8 *)((u8 *)state + 0x2b0) = *(u8 *)((u8 *)state + 0x2b0) & 0x7f | 0x80;
                if (lbl_803E53C0 < *(f32 *)((u8 *)state + 0x274)) {
                    *(f32 *)((u8 *)state + 0x274) = lbl_803E53C0;
                }
            }
        }
        playerObj = Obj_GetPlayerObject();
        if (hitObj == playerObj) {
            *(u16 *)state = 0x18e;
            ObjMsg_SendToObject(hitObj, 0x7000a, obj, state);
            *(u8 *)((u8 *)state + 0x2b0) = *(u8 *)((u8 *)state + 0x2b0) & 0xbf | 0x40;
        } else {
            *(f32 *)((u8 *)state + 0x274) -= timeDelta;
            if (*(f32 *)((u8 *)state + 0x274) <= lbl_803E5394) {
                Sfx_PlayFromObject(obj, 0xa2);
                (*(void (***)(void *))lbl_803DCA78)[5](obj);
                for (i = 0; i < 10; i++) {
                    objFn_800972dc(lbl_803E53B0, lbl_803E53B8, obj, 5, 7, 1, 0x3c, 0, 0);
                    (*(void (***)(void *, int, int, int, int, int))pDll_expgfx)[2](
                        obj, 0x3f3, 0, 4, -1, 0);
                }
                lightFn_8001db6c(lbl_803E53AC, *(void **)((u8 *)state + 0x270), 0);
                *(f32 *)((u8 *)state + 0x2a4) = lbl_803E53BC;
                *(s16 *)((u8 *)obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
            }
    }
}

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

    randAsDouble[1] = randomGetRange(0, 1000) ^ 0x80000000;
    randAsDouble[0] = 0x43300000;
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
        switch (*((u8 *)p5 + i + 0x81)) {
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
