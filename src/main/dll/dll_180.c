#include "ghidra_import.h"
#include "main/dll/dll_180.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80190148();
extern undefined4 FUN_801905c4();
extern void Transporter_SeqFn(void);
extern void objParticleFn_80097734(int obj,int enabled,f32 radius,int particleKind,
                                   int particleId,int lifetime,f32 scaleX,f32 scaleY,
                                   f32 scaleZ,void *args,int arg9);
extern void *objFindTexture(void *obj,int target,int param_3);

extern undefined4 DAT_803ddb38;

typedef struct CfDoorLightState {
  s32 textureId;
  u8 frameStep;
  u8 pad05[0x8 - 0x5];
  s32 maxFrame;
  s32 resetFrame;
  s32 currentFrame;
  u8 flags;
  u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightDef {
  u8 pad00[0x1e];
  s16 doneEvent;
  s16 triggerEvent;
} CfDoorLightDef;

typedef struct BarrelPadParticleArgs {
  u8 pad00[0xc];
  f32 offset[3];
} BarrelPadParticleArgs;

/*
 * --INFO--
 *
 * Function: transporter_init
 * EN v1.0 Address: 0x801916A0
 * EN v1.0 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->_0e per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->_0e & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */
#pragma peephole off
#pragma scheduling off
void transporter_init(int obj, u8 *params)
{
  u8 *state;
  int id;

  state = *(u8 **)(obj + 0xb8);
  *(s16 *)(state + 8) = 400;
  *(s8 *)(state + 0xe) = 0;
  *(s16 *)obj = (s16)((u16)(params[0x18] << 8));
  *(int *)(obj + 0xf4) = 0;
  *(void **)(obj + 0xbc) = (void *)Transporter_SeqFn;
  *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);

  id = *(int *)(params + 0x14);
  switch (id) {
  case 0x4670D:
  case 0x4827E:
  case 0x49267:
  case 0x4CB6A:
  case 0x4CB84:
    *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x68);
    break;
  case 0x48506:
  case 0x45753:
  case 0x463C0:
  case 0x45DD6:
  case 0x4977D:
  case 0x49C33:
  case 0x4B666:
  case 0x4B667:
    *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x08);
    break;
  case 0x4C986:
    *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x30);
    break;
  case 0x47064:
    *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x10);
    break;
  case 0x43F83:
    if (GameBit_Get(2984) != 0 || GameBit_Get(790) != 0 || GameBit_Get(1297) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  case 0x2BA7:
    if (GameBit_Get(3069) != 0 || GameBit_Get(666) != 0 || GameBit_Get(667) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  case 0x46A40:
    if (GameBit_Get(255) != 0 || GameBit_Get(2208) != 0 || GameBit_Get(2210) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  case 0x497F4:
    if (GameBit_Get(3182) != 0 || GameBit_Get(3184) != 0 || GameBit_Get(3185) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  case 0x4800C:
    if (GameBit_Get(3205) != 0 || GameBit_Get(3253) != 0 || GameBit_Get(3254) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  case 0x4A533:
    if (GameBit_Get(372) != 0 || GameBit_Get(3255) != 0 || GameBit_Get(3256) != 0) {
      *(u8 *)(state + 0xe) = (u8)(*(u8 *)(state + 0xe) | 0x20);
    }
    break;
  }

  if ((*(u8 *)(state + 0xe) & 0x40) != 0) {
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
  }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_801916e8
 * EN v1.0 Address: 0x801916E8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191BD4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801916e8(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x1a) != -1) {
    FUN_801905c4(param_1);
  }
  FUN_80190148(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80191730
 * EN v1.0 Address: 0x80191730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191C1C
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80191730(short *param_1,int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
void cflightwall_free(void) {}
void cflightwall_hitDetect(void) {}
void cflightwall_update(void) {}
void cflightwall_release(void) {}
void cflightwall_initialise(void) {}
void barrelpad_free(void) {}
void barrelpad_hitDetect(void) {}
void barrelpad_release(void) {}
void barrelpad_initialise(void) {}
void cf_doorlight_free(void) {}
void cf_doorlight_render(void) {}
void cf_doorlight_hitDetect(void) {}
void cf_doorlight_release(void) {}
void cf_doorlight_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int cflightwall_getExtraSize(void) { return 0x0; }
int cflightwall_getObjectTypeId(void) { return 0x0; }
int barrelpad_getExtraSize(void) { return 0x0; }
int barrelpad_getObjectTypeId(void) { return 0x0; }
int cf_doorlight_getExtraSize(void) { return 0x18; }
int cf_doorlight_getObjectTypeId(void) { return 0x0; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3EE8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F18;
extern f32 lbl_803E3F1C;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
#pragma scheduling off
#pragma peephole off
void cflightwall_render(void) { objRenderFn_8003b8f4(lbl_803E3EE8); }
void barrelpad_render(void) { objRenderFn_8003b8f4(lbl_803E3F00); }

void barrelpad_update(s16 *obj) {
    BarrelPadParticleArgs particleArgs;

    if (obj[0x23] == 0x79) {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F08;
        particleArgs.offset[2] = lbl_803E3F04;
        objParticleFn_80097734((int)obj,5,lbl_803E3F0C,5,2,0x19,lbl_803E3F10,
                               lbl_803E3F10,lbl_803E3F14,&particleArgs,0);
    }
    else if (obj[0x23] == 0x748) {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F18;
        particleArgs.offset[2] = lbl_803E3F04;
        objParticleFn_80097734((int)obj,5,lbl_803E3F1C,5,2,5,lbl_803E3F20,
                               lbl_803E3F20,lbl_803E3F14,&particleArgs,0);
    }
}

void barrelpad_init(s16 *obj, u8 *def) {
    obj[2] = (s16)((s32)def[0x18] << 8);
    obj[1] = (s16)((s32)def[0x19] << 8);
    obj[0] = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0) {
        *(f32 *)((char *)obj + 8) = (f32)(u32)def[0x1b] / lbl_803E3F24;
        if (*(f32 *)((char *)obj + 8) == lbl_803E3F04) {
            *(f32 *)((char *)obj + 8) = lbl_803E3F00;
        }
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * *(f32 *)((char *)*(int **)((char *)obj + 0x50) + 4);
    }
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}

extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;
void cflightwall_init(s16 *obj, u8 *def) {
    obj[2] = (s16)((s32)def[0x18] << 8);
    obj[1] = (s16)((s32)def[0x19] << 8);
    obj[0] = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0) {
        *(f32 *)((char *)obj + 8) = (f32)(u32)def[0x1b] / lbl_803E3EEC;
        if (*(f32 *)((char *)obj + 8) == lbl_803E3EF0) {
            *(f32 *)((char *)obj + 8) = lbl_803E3EE8;
        }
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * *(f32 *)((char *)*(int **)((char *)obj + 0x50) + 4);
    }
    *(u16 *)((char *)obj + 0xb0) |= 0xA000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cf_doorlight_update(int obj) {
    CfDoorLightState *state;
    CfDoorLightDef *def;
    int *textureFrame;

    state = *(CfDoorLightState **)(obj + 0xb8);
    def = *(CfDoorLightDef **)(obj + 0x4c);
    if ((((state->flags >> 5) & 1) == 0) && (GameBit_Get(def->triggerEvent) != 0) &&
        (((state->flags >> 6) & 1) == 0)) {
        state->flags = (state->flags & ~0x20) | 0x20;
        state->currentFrame = 0;
    }
    if (((state->flags >> 5) & 1) != 0) {
        textureFrame = objFindTexture((void *)obj,state->textureId,0);
        if (textureFrame != 0) {
            state->currentFrame += state->frameStep;
            if (state->currentFrame < 0) {
                state->currentFrame = 0;
            }
            else if (state->currentFrame > state->maxFrame) {
                if (def->doneEvent == -1) {
                    state->currentFrame = state->resetFrame;
                }
                else {
                    GameBit_Set(def->doneEvent,1);
                    state->flags = state->flags & ~0x20;
                    state->flags = (state->flags & ~0x40) | 0x40;
                    state->currentFrame = state->maxFrame;
                }
            }
            *textureFrame = state->currentFrame;
        }
    }
}

void cf_doorlight_init(int *obj, s8 *def) {
    register u8 *state = *(u8 **)((char *)obj + 0xb8);
    u32 b;
    *(int *)state = 0;
    *(s16 *)obj = (s16)((s32)def[0x19] << 9);
    *(int *)(state + 8) = (int)*(s16 *)((char *)def + 0x1a) << 8;
    *(u8 *)(state + 4) = (u8)*(s16 *)((char *)def + 0x1c);
    *(int *)(state + 0xc) = (int)def[0x18] << 8;
    b = (u32)(u8)GameBit_Get(*(s16 *)((char *)def + 0x1e));
    state[0x14] = (u8)((state[0x14] & ~0x40) | ((b & 1) << 6));
    if (((u32)state[0x14] >> 6) & 1) {
        *(int *)(state + 0x10) = *(int *)(state + 8);
        state[0x14] |= 0x20;
    }
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
    *(u16 *)((char *)obj + 0xb0) |= 0x4000;
}
#pragma peephole reset
#pragma scheduling reset
