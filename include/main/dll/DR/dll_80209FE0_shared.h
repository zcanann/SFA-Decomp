#ifndef MAIN_DLL_DR_DLL_80209FE0_SHARED_H_
#define MAIN_DLL_DR_DLL_80209FE0_SHARED_H_

#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/maketex.h"
#include "main/objHitReact.h"
#include "main/render.h"
#include "main/objhits.h"
#include "main/objanim.h"
#include "main/objanim_update.h"

extern u32 SnowBike_hitDetect();
extern double SeekTwiceBeforeRead();
extern u32 countLeadingZeros();

extern f64 DOUBLE_803e7188;
extern f64 DOUBLE_803e71c0;
extern f64 DOUBLE_803e7218;
extern f64 DOUBLE_803e7238;
extern f64 DOUBLE_803e7250;
extern f64 DOUBLE_803e7270;
extern f64 DOUBLE_803e72a8;
extern f64 DOUBLE_803e72d0;
extern f64 DOUBLE_803e7308;
extern f64 DOUBLE_803e7358;
extern f64 DOUBLE_803e7398;
extern f64 DOUBLE_803e73b0;
extern f64 DOUBLE_803e7428;
extern f64 DOUBLE_803e7478;
extern f64 DOUBLE_803e7498;
extern f64 DOUBLE_803e74f8;
extern f64 DOUBLE_803e7500;
extern f64 DOUBLE_803e7520;
extern f64 DOUBLE_803e7528;
extern f64 DOUBLE_803e7540;
extern f64 DOUBLE_803e7560;
extern f64 DOUBLE_803e7568;
extern f64 DOUBLE_803e7570;
extern f64 DOUBLE_803e75c8;
extern f64 DOUBLE_803e7608;
extern f64 DOUBLE_803e7618;
extern f64 DOUBLE_803e7648;
extern f64 DOUBLE_803e76b8;
extern f64 DOUBLE_803e76f8;
extern f64 DOUBLE_803e7700;
extern f64 DOUBLE_803e7768;
extern f64 DOUBLE_803e7790;
extern f64 DOUBLE_803e7838;
extern f64 DOUBLE_803e78e0;
extern f64 DOUBLE_803e78e8;
extern f64 DOUBLE_803e7960;
extern f64 DOUBLE_803e7998;
extern f64 DOUBLE_803e79e0;
extern f64 DOUBLE_803e7a30;
extern f64 DOUBLE_803e7a60;
extern f64 DOUBLE_803e7aa0;
extern f64 DOUBLE_803e7ae8;
extern f64 DOUBLE_803e7b18;
extern f64 DOUBLE_803e7b20;
extern f64 DOUBLE_803e7b58;
extern f64 DOUBLE_803e7b78;
extern f64 DOUBLE_803e7b80;
extern f64 DOUBLE_803e7be0;
extern f64 DOUBLE_803e7be8;
extern f64 DOUBLE_803e7cb8;
extern f64 DOUBLE_803e7ce8;
extern f64 DOUBLE_803e7d00;
extern f64 DOUBLE_803e7d08;
extern f64 DOUBLE_803e7d28;
extern f64 DOUBLE_803e7d30;
extern f64 DOUBLE_803e7d68;
extern f64 DOUBLE_803e7d90;
extern f64 DOUBLE_803e7da8;
extern f64 DOUBLE_803e7dc0;
extern f64 DOUBLE_803e7dc8;
extern f64 DOUBLE_803e7de0;
extern f64 DOUBLE_803e7df0;
extern f64 DOUBLE_803e7e10;
extern f64 DOUBLE_803e7e18;
extern f64 DOUBLE_803e7ea0;
extern f64 DOUBLE_803e7ea8;
extern f64 DOUBLE_803e7ec0;
extern f64 DOUBLE_803e7ed0;
extern f64 DOUBLE_803e7ee0;
extern f64 DOUBLE_803e7ef0;
extern f64 DOUBLE_803e7f00;
extern f64 DOUBLE_803e7f10;
extern f64 DOUBLE_803e7f18;
extern f64 DOUBLE_803e7f38;
extern f64 DOUBLE_803e7f40;
extern f64 DOUBLE_803e7f70;
extern f64 DOUBLE_803e7f78;
extern f64 DOUBLE_803e7f98;
extern f64 DOUBLE_803e7fc8;
extern f64 DOUBLE_803e7fe0;
extern f64 DOUBLE_803e7fe8;
extern f64 DOUBLE_803e7ff0;
extern f64 DOUBLE_803e8038;
extern f64 DOUBLE_803e8060;
extern f64 DOUBLE_803e8088;
extern f64 DOUBLE_803e8090;
extern f64 DOUBLE_803e80a8;
extern f64 DOUBLE_803e80c0;
extern f64 DOUBLE_803e80d0;
extern f64 DOUBLE_803e80e0;
extern f64 DOUBLE_803e8130;
extern f64 DOUBLE_803e81d8;
extern f64 DOUBLE_803e8200;
extern f64 DOUBLE_803e8208;
extern f64 DOUBLE_803e8220;
extern f64 DOUBLE_803e8238;
extern f64 DOUBLE_803e8268;
extern f64 DOUBLE_803e8280;

extern void Music_Trigger(int id, int value);
extern void objRenderModelAndHitVolumes(int, int, int, int, int, f32);
extern int bossdrakor_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E6588;
extern f32 gThornBushLightScaleMax;
extern f32 lbl_803E6590;
extern f32 lbl_803E6594;
extern f32 lbl_803E651C;
extern f32 lbl_803E6510;
extern f32 lbl_803E657C;
extern f32 lbl_803E65C0;
extern f32 lbl_803E65C4;
extern f32 lbl_803E65C8;
extern int arrayIndexOf();
extern f32 lbl_803E6598;
extern f32 lbl_803E65A8;
extern f32 gThornBushLightScaleRate;
extern f32 lbl_803E65B0;
extern f32 lbl_803E65B8;
extern void drakorhoverpad_resetPendingMotion(GameObject* obj);
extern f32 lbl_803E6540;
extern f32 lbl_803E6544;
extern f32 lbl_803E6548;
extern f32 lbl_803E654C;
extern int gBossDrakorMoveStateTable[];
extern int Obj_RemoveFromUpdateList(int* obj);
extern void gameTextShow(int id);
extern void timeOfDayFn_80055000(void);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern f32 lbl_803E6514;
extern f32 lbl_803E6518;
extern f32 lbl_803E6520;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6558;
extern f32 lbl_803E655C;
extern int gThornBushLightningHitTable;
extern int gThornBushThornHitTable;
extern f32 gThornBushLightningTimerInit;

typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} DrakorFlags;

extern void PSVECSubtract(f32* a, f32* b, f32* out);
extern void PSVECNormalize(f32* in, f32* out);
extern f32 PSVECDotProduct(f32* a, f32* b);
extern void PSVECScale(f32* in, f32* out, f32 scale);
extern f32 PSVECMag(f32* v);
extern void drakormissile_startActiveLaunch(GameObject* obj);
extern void timeOfDayFn_80055038(void);
extern int randFn_80080100(int range);
extern int gBossDrakorMoveSpeedTable[];
extern int gBossDrakorTurnMoveStates[];
extern s16 lbl_803DC198;
extern s16 lbl_803DC19A;
extern f32 lbl_803DC188;
extern f32 lbl_803DC18C;
extern f32 lbl_803DC190;
extern f32 lbl_803DC194;
extern f32 gBossDrakorDegToAngle;
extern f32 lbl_803E6534;
extern f32 lbl_803E6538;
extern f32 lbl_803E653C;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E656C;
extern f32 lbl_803E6570;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;

void bossdrakor_handleActionEvent(int obj, int state, int action);
void bossdrakor_updateHeadTracking(GameObject* obj, int state);
int bossdrakor_chooseNextMove(GameObject* obj, f32* speedOut);
void bossdrakor_spawnAttackObjects(GameObject* obj, int state, int action);

#endif
