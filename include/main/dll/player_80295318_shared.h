#ifndef SFA_DLL_PLAYER_80295318_SHARED_H
#define SFA_DLL_PLAYER_80295318_SHARED_H

#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_transform.h"
#include "main/object.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objseq_api.h"
#include "main/shader_api.h"
#include "main/dll/player_state.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/render.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_status.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/byte_flags.h"
#include "main/pad.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "string.h"

/* external symbol declarations */
extern void fn_8005D108();
extern u32 FUN_8006f764();
extern u32 FUN_80070ec8();
extern u32 FUN_80071d70();
extern u32 FUN_80071f8c();
extern u32 FUN_80071f90();
extern int FUN_8007f3c8();
extern int FUN_8007f7c0();
extern int FUN_8007f810();
extern u32 FUN_80080f34();
extern u32 FUN_80080f3c();
extern u32 FUN_800810d8();
extern u32 FUN_800810dc();
extern u32 FUN_800810f4();
extern u32 FUN_800810f8();
extern u32 FUN_80081110();
extern u32 FUN_8008111c();
extern u32 FUN_80081120();
extern u32 FUN_80081124();
extern f32 lbl_803E7EA4;
extern f32 lbl_803E7FF0;
extern f32 lbl_803E7FB4;
extern f32 lbl_803E7FB0;
extern f32 lbl_803DC6D4;
extern f32 lbl_803DC6D8;
extern f32 lbl_803DC6DC;
extern f32 lbl_803DC6E0;
extern f32 lbl_803DC6E4;
extern f32 lbl_803E7ED4;
extern f32 lbl_803E7EF0;
extern f32 lbl_803E8060;
extern f32 lbl_803E7F4C;
extern int* gBaddieControlInterface;
extern f32 lbl_803E80EC;
extern f32 lbl_803E7FD4;
extern f32 lbl_803E7FCC;
extern f32 lbl_803E7EDC;
extern f32 lbl_803E7EF4;
extern f32 lbl_803E7F04;
extern f32 lbl_803E80A8;
extern f32 lbl_803DC6B8;
extern f32 lbl_803E7EE4;
extern f32 lbl_803E7EE8;
extern f32 lbl_803E7EEC;
extern void fn_8011F6E0(int button, u8 angle, int mag);
extern void fn_8011F6D4(int flag);
extern f32 lbl_803E8178;
extern f32 lbl_803E7E90;
extern f32 lbl_803E8040;
extern f32 lbl_803E8044;
extern f32 lbl_803E8048;
extern f32 lbl_803E804C;
extern f32 lbl_803E8018;
extern f32 lbl_803E8038;
extern const f32 lbl_803E7EE0;
extern f32 lbl_803E7F6C;
extern f32 lbl_803E7F58;
extern f32 lbl_803E7F9C;
extern f32 lbl_803E80BC;
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int*** out, int a, int b);
extern f32 lbl_803E7F98;
extern void objRenderFuzz(int obj);
extern void objRenderFn_800413d4(int obj);
extern void fuzzRenderFn_800412dc(int obj);
extern s16 lbl_803DC6C4;
extern f32 lbl_803E7F50;
extern f32 lbl_803E80C4;
extern f32 lbl_803E7FA0;
extern f32 lbl_803E7FA4;
extern const f32 lbl_803E7F5C;
extern f32 lbl_803E8150;
extern f32 lbl_803E81AC;
extern f32 lbl_803E81B0;
extern f32 lbl_803E81B8;
extern f32 lbl_803E81BC;
extern f32 lbl_803E81A8;
extern f32 lbl_803E7F08;
extern f32 lbl_803E7FD8;
extern f32 lbl_803E801C;
extern f32 lbl_803E7F10;
extern f32 lbl_803E811C;
extern f32 lbl_803E80E4;
extern const f32 lbl_803E7ED8;
extern f32 lbl_803DC670;
extern f32 lbl_803DC674;
extern f32 lbl_803DC678;
extern f32 lbl_803E81DC;
extern f32 lbl_803E81E0;
extern f32 lbl_803E81E4;
extern f32 lbl_803E81E8;
extern f32 lbl_803E81EC;
extern f32 lbl_803E81F0;
extern f32 lbl_803E81F4;
extern f32 lbl_803E81F8;
extern f32 lbl_803E81FC;
extern f32 lbl_803E8200;
extern f32 lbl_803E8204;
extern f32 lbl_803E8208;
extern f32 lbl_803E813C;
extern void fn_8011F34C(int a);
extern f32 lbl_803E7F34;
extern f32 lbl_803DC690;
extern int lbl_803DC688;
extern f32 lbl_803DC67C;
extern f32 lbl_803DC684;
extern f32 lbl_803E81CC;
extern f32 lbl_803E81D4;
extern f32 lbl_803E81D8;
extern f32 lbl_803E7FE8;
extern f32 lbl_803E8058;
extern f32 lbl_803E7F44;
extern f32 lbl_803E7F48;
extern f32 lbl_803E7EF8;
extern f32 lbl_803E812C;
extern f32 lbl_803E7F28;
extern f32 lbl_803E7F2C;
extern f32 lbl_803E7F40;
extern f32 lbl_803E805C;
extern f32 lbl_803E7F20;
extern f32 lbl_803E7F14;
extern f32 lbl_803E7F18;
extern f32 lbl_803E7F24;
extern f32 lbl_803E7FC0;
extern f32 lbl_803E7F0C;
extern int audioPickSoundEffect_8006ed24(u8 id, int bank);
extern f32 lbl_803E820C;
extern f32 lbl_803E7EB4;
extern void playerShadowFn_80062a30(int obj);
extern f32 lbl_803E80E8;
extern f32 lbl_803E7EFC;
extern f32 lbl_803E8070;
extern f32 lbl_803E7F30;
extern f32 lbl_803E800C;
extern f32 lbl_803E8138;
extern f32 lbl_803E8050;
extern f32 lbl_803E7FAC;
extern f32 lbl_803E8008;
extern s16 lbl_803DC69C;
extern s16 lbl_803DC698;
extern f32 lbl_803E80CC;
extern f32 lbl_803E80D0;
extern f32 lbl_803E7FBC;
extern f32 lbl_803E7F68;
extern f32 lbl_803E7F84;
extern f32 lbl_803E8184;
extern f32 lbl_803E818C;
extern f32 lbl_803E8190;
extern f32 lbl_803E8194;
extern f32 lbl_803E8140;
extern f32 lbl_803E8148;
extern f32 lbl_803E814C;
extern f32 lbl_803E80F4;
extern f32 lbl_803E80F8;
extern f32 lbl_803E7FC4;
extern f32 lbl_803E8210;
extern int lbl_803DC6A4;
extern f32 lbl_803DC6C0;
extern f32 lbl_803E8144;
extern f32 lbl_803E8168;
extern f32 lbl_803E816C;
extern f32 lbl_803E8170;
extern f32 lbl_803E8174;
extern f32 lbl_803E7FFC;
extern f32 lbl_803E7EC8;
extern f32 lbl_803E7ECC;
extern f32 lbl_803E7ED0;
extern f32 lbl_803E80D4;
extern f32 lbl_803E80D8;
extern f32 lbl_803E80AC;
extern f32 lbl_803E7E80;
extern f32 lbl_803E7E84;
extern f32 lbl_803E7E88;
extern f32 lbl_803E7E8C;
extern f32 lbl_803E7E94;
extern f32 lbl_803E7E98;
extern f32 lbl_803E7E9C;
extern f32 lbl_803E7EA8;
extern f32 lbl_803E7EAC;
extern f32 lbl_803E7EB0;
extern f32 lbl_803E7EB8;
extern f32 lbl_803E7EBC;
extern f32 lbl_803E7FC8;
extern f32 lbl_803E7FF4;
extern f32 lbl_803E7F1C;
extern int lbl_803DCF34;
extern int lbl_803DCF38;
extern f32 lbl_803E80C8;
extern int hitDetectFn_800658a4(int a, void* p, int flag, f32 x, f32 y, f32 z);
extern f32 lbl_803E8024;
extern f32 lbl_803E8028;
extern f32 lbl_803E802C;
extern f32 lbl_803E8010;
extern f32 lbl_803E7FEC;
extern f32 lbl_803E8014;
extern f32 lbl_803E8114;
extern f32 lbl_803E8118;
extern f32 lbl_803E8124;
extern f32 lbl_803E8128;
extern f32 lbl_803E808C;
extern void fn_80189C68(int a);
extern f32 lbl_803E7F54;
extern f32 lbl_803E7F60;
extern f32 lbl_803E7F64;
extern f32 lbl_803E7F70;
extern f32 lbl_803E7F74;
extern f32 lbl_803E7F78;
extern f32 lbl_803E7F7C;
extern f32 lbl_803E7F80;
extern double lbl_803E7F88;
extern f32 lbl_803E7F90;
extern int objBboxFn_800640cc(f32 radius, void* from, void* to, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E7FA8;
extern f32 lbl_803E8068;
extern f32 lbl_803E806C;
extern f32 lbl_803E7EA0;
extern f32 lbl_803DC680;
extern f32 lbl_803E7FD0;
extern f32 lbl_803E80E0;
extern f32 lbl_802C2BF0[];
extern u8 lbl_802C2B30[];
extern void setTextColor(u32* objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void fn_80078740(void);
extern void drawFn_8005cf8c(void* matrix, void* displayList, int count);
extern f32 lbl_803E8130;

/* forward declarations for graduated functions */
void playerUpdateTail(int a, int b, f32* vec, int c, int mode, f32 angle);
void playerDoTailAnims(int obj, void* statep);
void playerUpdatePathEffectCountdown(GameObject* obj, int inner);
int playerStopRidingObject(GameObject* obj);
void fn_80295918(int obj, int sel, f32 fval);
int fn_80295A04(GameObject* obj, int sel);
void objSetPos(GameObject* obj, f32 f1, f32 f2, f32 f3);
int objIsCurModelNotZero(void* obj);
int isTrickyNear(int obj);
int fn_80295C0C(GameObject* obj);
int fn_80295C24(GameObject* obj);
int fn_80295C40(GameObject* obj);
int fn_80295C5C(GameObject* obj);
int fn_80295C88(int obj);
int fn_80295CBC(GameObject* obj);
int playerIsDisguised(int obj);
int playerIsPathFollowing(int obj);
void staffToggle(GameObject* obj, int a);
void playerSetDisguised(GameObject* obj, int mode);
int fn_8029605C(GameObject* obj, f32* outX, f32* outY);
void fn_802960E4(void);
void fn_802960E8(void* playerObj, s16 effectId);
void fn_802960F4(GameObject* obj, int* out);
f32 fn_8029610C(GameObject* obj);
void fn_80296124(GameObject* obj, void* p2, void* p3);
void fn_802961A4(int obj, int* out1, f32* out2);
void fn_802961FC(int a, u8 type);
int Obj_IsParentSlackClear(GameObject* obj);
int fn_80296240(GameObject* obj);
int fn_8029630C(GameObject* obj);
int objAnimFn_80296328(int obj);
int playerGetFlags3F0Bit5(GameObject* obj);
int EmissionController_IsLingering(GameObject* obj);
int fn_80296464(int obj);
void playerSetHaveSpell(GameObject* obj, int spell, int set);
int playerHasSpell(GameObject* obj, int spell);
int objGetAnimStateFlags(GameObject* obj, int flag);
int playerSetHeldObject(int obj, int held);
int fn_8029669C(int obj);
int fn_802966B4(GameObject* obj);
f32 fn_802966F4(GameObject* obj);
int objFn_80296700(int obj);
void playerPutAwayStaff(GameObject* obj, int mode);
void playerPullOutStaff(GameObject* obj, int mode);
void playerAddRemoveMagic(GameObject* obj, int amount);
void saveSetOverrideHealth(int v);
void playerCancelSpell(GameObject* obj, int p2);
void fn_80296BBC(GameObject* obj);
void cameraGetPrevPos2(GameObject* obj, f32* x, f32* y, f32* z);
void playerLock(GameObject* obj, int lock);
int playerStatusIsPositive(GameObject* obj);
int fn_80296C4C(int obj);
int playerIsDead(int obj);
void playerSetIsDead(GameObject* obj, int flag);
void playerHeal(GameObject* obj);
void fn_80296D20(int obj, void* arg);
void playerSetInCutscene(GameObject* obj);
void playerSetCutsceneCameraFlag(GameObject* obj);
void playerSetOverrideParentSlack(GameObject* obj);
u32 playerGetStateFlag310(GameObject* obj);
void fn_802972B4(GameObject* obj, int* flags, f32* p5, f32* p6, f32* p7, s16* p8);
int fn_80297498(void);
int playerState41(GameObject* obj, int state, f32 fv);
int playerState40(int p1, int obj);
int playerState3F(int obj, int state);
int playerStateNop3E(void);
void fn_8029782C(GameObject* obj);
int playerState3D(int obj, int state, f32 fv);
int playerState3C(GameObject* obj, int state, f32 fv);
int playerState3B(GameObject* obj, int state, f32 fv);
int playerState3A(GameObject* obj, int state, f32 fv);
int playerState39(GameObject* obj, int state, f32 fv);
int playerState38(GameObject* obj, int state, f32 fv);
int playerState37(GameObject* obj, int state);
void fn_802985AC(GameObject* obj);
int playerStateSuperQuake(GameObject* obj, int state, f32 fv);
void fn_80298924(int obj);
int playerState35(GameObject* obj, int state);
int playerState34(GameObject* obj, int state);
int playerStateStaffLiftRock(int obj, int state, f32 fv);
void fn_802994A4(GameObject* obj);
int playerStateStaffBoost(GameObject* obj, int state, f32 fv);
int playerState31(GameObject* obj, int p2);
int playerState30(GameObject* obj, int state, f32 fv);
void fn_8029A420(GameObject* obj);
void fn_8029A4A8(GameObject* obj, int p2);
int playerStateFireLaser(int obj, int state);
int playerStateShootFireball(GameObject* obj, int state, f32 fv);
int playerStateTryCastSpell(GameObject* obj, int state, f32 fv);
int playerStateStopAimStaff(int obj, int state);
int playerStateStartAimStaff(GameObject* obj, int state);
int playerState29(GameObject* obj, int state);
int playerState28(GameObject* obj, int state, f32 fv);
void fn_8029BC08(GameObject* obj);
int playerState27(GameObject* obj, int state, f32 fv);
void fn_8029C8C8(GameObject* obj, int p2);
int playerState25(int obj, int state);
int playerState24(GameObject* obj, int state, f32 fv);
int playerState23(GameObject* obj, int state, f32 fv);
int playerState22(GameObject* obj, int state);
int playerState21(int obj, int state, f32 fv);
int playerState20(GameObject* obj, int state, f32 fv);
int playerState1F(GameObject* obj, int state, f32 fv);
int playerState1E(int obj, int state);
void fn_8029DAE0(GameObject* obj, int* p2);
int playerState1C(GameObject* obj, int state);
int playerState1B(GameObject* obj, int state, f32 fv);
int playerStateOnCloudRunner(GameObject* obj, int state);
int playerState19(GameObject* obj, int state);
void fn_8029F67C(GameObject* obj);
int playerStateOnBike(GameObject* obj, int state);
int playerState17(int p1, int state);
int playerStateMountBike(GameObject* obj, int state, f32 fv);
void fn_8029FFD0(GameObject* obj, int p2);
void objUpdateHitboxPos(int obj);
int playerStateClimbDownFromWall(GameObject* obj, int state);
int playerStateClimbUpFromWall(GameObject* obj, int state);
int playerStateClimbOntoWall(GameObject* obj, int state);
void playerPlayClimbingSound(GameObject* obj, int p2);
int playerState11(GameObject* obj, int state);
int playerStateSlideDownLadder(GameObject* obj, int state, f32 fv);
int playerStateClimbOntoLadder(GameObject* obj, int state, f32 fv);
int playerState0D(GameObject* obj, int p2);
int playerState0B(GameObject* obj, int state);
int playerStateGrabLedge(GameObject* obj, int state);
int playerState09(GameObject* obj, int state);
void fn_802A49A8(GameObject* obj);
int playerStateThrowing(GameObject* obj, int state);
void fn_802A4B4C(GameObject* obj);
int playerState06(GameObject* obj, int state);
int playerState05(GameObject* obj, int state);
int playerState04(int obj, int state, f32 fv);
int playerStateIceSpell(int obj, int state, f32 fv);
void fn_802A514C(GameObject* obj, int state);
int playerState00(int obj, int state);
int fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags);
void fn_802A81B8(GameObject* obj, int state, f32* out);
int fn_802A8350(int obj, int p4, int src, int dst, int flag);
int fn_802A8680(int p1, int p2, int src, int vec, int out, int flag);
int fn_802A8EE4(int a, int b, int c, int d, int e);
void fn_802A93F4(GameObject* obj, int p2, int p3);
void playerCastIceSpell(void);
int fn_802A97D0(GameObject* obj, int p2);
int playerCanCastPortalOpenSpell(GameObject* obj, int p2);
int playerCanCastQuakeSpell(GameObject* obj, int p2);
int playerCanCastBlasterSpell(GameObject* obj, int p2, int p3);
int playerIsBlasterSpellAvailable(GameObject* obj, int p2, int p3);
void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8);
void fn_802AA014(GameObject* obj);
void fn_802AA2B0(int obj, int state, f32 unused, f32 yoff);
void staffShootFireball(GameObject* obj, int p2, f32 unused);
void objDoTeleportAnim(GameObject* obj);
void playerDie(GameObject* obj);
void fn_802AABE4(int obj);
void playerDrawTeleportAnim(GameObject* obj);
void fn_802AAF80(GameObject* obj, int inner, int a, int b, int c);
int fn_802AB1D0(GameObject* obj);
void playerCastSpell(int a, int b, int c);
void fn_802AB5A4(GameObject* obj, int p2, int flags);
void playerCalcWaterCurrent(f32* outX, f32* outZ, int player);
int fn_802ABAE8(GameObject* obj, int state, int inner, f32 fv);
void fn_802ABFBC(GameObject* obj, int state, PlayerState* inner);
void fn_802AC32C(int p1, int p2, int p3);
void playerSetMovingAnims(int p1, int obj);
int fn_802ADC08(GameObject* obj, int inner, int p3);
void fn_802ADE80(GameObject* obj, int inner, int state);
int fn_802AE480(GameObject* obj, int inner, int state);
void fn_802AE650(GameObject* obj, int state, int p3);
void fn_802AE83C(int obj, int inner);
void fn_802AE9C8(GameObject* obj, int inner, int state);
void fn_802AED2C(GameObject* obj, int state, int p3);
void staffAnimate(int obj, int state);
void playerProcessQueuedItemCommand(GameObject* obj, int state);
void playerRunActiveSpells(GameObject* obj, int state);
void fn_802B066C(GameObject* obj, int state);
void playerStaffInit(GameObject* obj, int state);
void playerDoEyeAnims(GameObject* obj, int state);
void fn_802B18BC(GameObject* obj, int state, f32 fv);
void playerDoControls(GameObject* obj, int state, f32 fv);
void fn_802B1E5C(GameObject* obj, int state, int cfg, f32 dt);
void fn_802B2DA4(void);
void fn_802B4A9C(int obj, int inner, int inner2);
void playerAnimate(int obj, int state, f32 fv);
void fn_802B4DE0(GameObject* obj);
void fn_802B4ED8(GameObject* obj, int p2, int mode);
void playerUpdateWhileTimeStopped(int obj);
void objLoadPlayerFromSave(int obj);
void playerInitFuncPtrsEntry(int obj);
void playerInitFuncPtrs(int obj);
extern f32 vec3f_distanceSquared(void* a, void* b);
extern void hudFn_8011f38c(int arg);
extern void __set_debug_bba(int a);
#endif
