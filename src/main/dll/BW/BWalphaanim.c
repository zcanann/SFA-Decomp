#include "main/dll/BW/BWalphaanim.h"
#include "main/game_object.h"


extern undefined4 FUN_8000680c();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a10();
extern undefined4 FUN_80017a80();
extern int FUN_80053c14();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern uint FUN_801eb0c0();
extern undefined4 fn_801EAE4C();
extern undefined4 fn_801EB0D4();
extern undefined4 fn_801EB634();
extern void fn_801EC1AC(int obj, int state);
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80293130();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E6838;
extern f32 lbl_803E68B0;

extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;

void SnowBike_release(void);

void SnowBike_initialise(void);

void SB_CloudRunner_onSeqFree(int* obj)
{
    SnowBikeState* p = (SnowBikeState*)obj[0xb8 / 4];
    p->riderPosX = ((GameObject*)obj)->anim.localPosX;
    p->riderPosY = ((GameObject*)obj)->anim.localPosY;
    p->riderPosZ = ((GameObject*)obj)->anim.localPosZ;
    {
        s32 v = *(s16*)obj - 0x4000;
        p->riderYawOnFree = (s16)v;
    }
    p->riderPitchOnFree = ((GameObject*)obj)->anim.rotZ;
}

extern char lbl_803284E0[];
extern u32 lbl_803E5AE0;
extern u8* mmAlloc(int size, int tag, int a);
extern void* memcpy(void* dst, const void* src, int n);
extern void Obj_ClearModelSlotIndex(int obj);
extern void fn_801EC928(int obj, u8* state);
extern void SnowBike_animEventCallback();
extern void ObjGroup_AddObject(int obj, int group);
extern f32 lbl_803DC0B8;
extern f32 lbl_803DC0C0;
extern f32 lbl_803DC0C4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C54;
extern f32 lbl_803E5C58;
extern f32 lbl_803E5C5C;
extern f32 lbl_803E5C60;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;

typedef struct
{
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;

void SnowBike_init(int obj, u8* params, int flag);


extern void Obj_SetModelSlotIndex(int obj, int slot);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int drshackle_updateAttachedPosition(int obj, u8* state);
extern void fn_801EBD60(int obj, u8* state);
extern void fn_801EC7A0(int obj, u8* state);
extern void fn_801EA240(int obj, u8* state, f32 speed, int val, u8* p, int n);

typedef struct
{
    s16 rot[3];
    f32 quad[4];
} SBRotQuad;

extern void objApplyVelocity(int obj);
extern int Rcp_GetMotionBlurEnabled(void);
extern void setMotionBlur(int a, f32 b);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void PSVECAdd(f32 * a, f32 * b, f32 * dst);
extern void mtxRotateByVec3s(f32 * mtx, s16 * rot);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 powfBitEstimate(f32 x, f32 y);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern char padGetStickX(int pad);
extern char padGetStickY(int pad);
extern u32 getButtonsHeld(int pad);
extern u32 getButtonsJustPressed(int pad);
extern u32 getButtonsJustPressedIfNotBusy(int pad);
extern int getAngle(f32 dx, f32 dz);
extern f32 timeDelta;
extern f32 lbl_803E5B6C;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5C18;

