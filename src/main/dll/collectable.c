#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "dolphin/mtx.h"
#include "main/dll/collectable.h"
#include "main/dll/baddie/skeetla.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/objhits_types.h"


#define TRICKY_STATE_FLAG_FLOOR_RESPONSE 0x00100000
#define TRICKY_STATE_FLAG_SPECIAL_FLOOR_RESPONSE 0x08000000
#define TRICKY_STATE_FLAG_SPECIAL_FLOOR_ABOVE 0x10000000
#define TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT 0x00000008
#define TRICKY_CONTROL_FLAG_USE_SPECIAL_FLOOR_Y 0x08000000
#define TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y 0x20000000
#define TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK 0x28000002
#define TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR 0x10
#define TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID 0x46406
#define TRICKY_HEIGHT_TRACK_GROUP 0x51
#define TRICKY_HEIGHT_TRACK_MODEL_SLOT 3
#define TRICKY_BBOX_HIT_SCRATCH_SIZE 84

#include "main/dll/tricky_state.h"

typedef struct TrickyInitFlags {
  u8 initBit7 : 1;
  u8 bit6 : 1;
  u8 bit5 : 1;
  u8 bit4 : 1;
  u8 bit3 : 1;
  u8 bit2 : 1;
  u8 bit1 : 1;
  u8 bit0 : 1;
} TrickyInitFlags;

typedef struct TrickyStatusFlags58 {
  u8 bit7 : 1;
  u8 bit6 : 1;
  u8 heightTracking : 1;
  u8 bit4 : 1;
  u8 bit3 : 1;
  u8 bit2 : 1;
  u8 bit1 : 1;
  u8 bit0 : 1;
} TrickyStatusFlags58;

extern undefined4 FUN_800067e8();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined8 FUN_800068cc();
extern undefined8 FUN_800068d0();
extern char FUN_80006a64();
extern undefined4 FUN_80006a68();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void Sfx_RemoveLoopedObjectSound(int param_1,int param_2);
extern int Sfx_IsPlayingFromObjectChannel(int param_1,int param_2);
extern int Sfx_PlayFromObject(int obj,int sfxId);
extern int Sfx_PlayFromObjectLimited(int obj,int sfxId,int maxCount);
extern undefined8 FUN_800178ec();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a30();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int voxmaps_traceLine(void *from,void *to,int param_3,u8 *hit,int param_5);
extern void voxmaps_worldToGrid(Vec *world,void *grid);
extern void* ObjList_FindObjectById(int objId);
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern int getTrickyObject(void);
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_SyncObjectPosition();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject(int group,int obj,f32 *maxDistance);
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int Obj_GetActiveModel(int obj);
extern int Obj_GetPlayerObject(void);
extern undefined8 ObjLink_DetachChild();
extern undefined8 ObjLink_AttachChild();
extern void Obj_FreeObject(int param_1);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject(int setup,int param_2,int param_3,int param_4,int param_5);
extern u8 Obj_IsLoadingLocked(void);
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAnimFn_80038f38();
extern undefined8 FUN_80039468();
extern void objAudioFn_800393f8(int param_1,void *param_2,int param_3,int param_4,int param_5,
                                int param_6);
extern int FUN_8003964c();
extern f32 getXZDistance(f32 *a, f32 *b);
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int objModelGetVecFn_800395d8(int obj,int param_2);
extern undefined4 FUN_80046f44();
extern undefined4 FUN_80046f84();
extern void freeAndNull(void *param_1);
extern void trickyVoxAllocFn_8004b5d4(void *param_1);
extern int ViewFrustum_IsSphereVisible(f32 *pos,f32 radius);
extern undefined8 FUN_800571f8();
extern int FUN_800575b4();
extern int FUN_800620e8();
extern u16 hitDetectFn_80065e50(f32 x,f32 y,f32 z,int obj,int *hits,int param_6,int param_7);
extern undefined4 FUN_8006dca8();
extern void objAudioFn_8006edcc(f32 param_1,f32 param_2,int obj,u16 param_4,int param_5,float *points,void *aux);
extern void objAudioFn_8006ef38(int obj,int joint,int pointCount,int pathPoints,int scratch,f32 scaleX,f32 scaleY);
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_800da700();
extern undefined8 FUN_800da850();
extern undefined4 FUN_800db47c();
extern ushort FUN_800db690();
extern undefined4 FUN_800dbc68();
extern undefined8 FUN_800dd3dc();
extern undefined4 FUN_800dd3e0();
extern void doNothing_onTrickyFree(void);
extern void doNothing_onTrickyInit(void);
extern void walkgroupFindExitPointFn_800dc398(void);
extern void gameBitIncrement(int eventId);
extern u32 GameBit_Get(int bit);
extern void GameBit_Set(int eventId,int value);
extern undefined8 FUN_80135d54();
extern void objAnimFreeChildren(int param_1,int param_2,int *param_3);
extern void trickyImpress(int obj);
extern int trickyFoodFn_8014460c(int obj,int state);
extern void objAnimFn_8013a3f0(int obj,int animId,f32 blend,int flags);
extern undefined4 FUN_80135f38();
extern undefined4 FUN_80136310();
extern undefined4 FUN_8013651c();
extern int trickyFindNearestUsableBaddie(int obj,int param_2,f32 maxRadius);
extern undefined4 FUN_801367b4();
extern int FUN_80136870();
extern void fn_8013ADFC(int obj);
extern void Tricky_emitQueuedPathParticles(int obj,int state);
extern int trickyFn_8013b368();
extern int trickyGrowl();
extern int FUN_801451dc();
extern undefined4 FUN_8014fef8();
extern byte FUN_80150620();
extern undefined4 FUN_801523bc();
extern undefined4 FUN_80152b8c();
extern undefined4 FUN_80152f54();
extern undefined4 FUN_80153440();
extern undefined4 FUN_80153db4();
extern undefined4 FUN_80154108();
extern undefined4 FUN_80154cc8();
extern undefined4 FUN_80157168();
extern undefined4 FUN_80158540();
extern undefined4 FUN_80159c60();
extern undefined4 FUN_8015a4c4();
extern undefined4 FUN_8015b2cc();
extern undefined4 FUN_801778d0();
extern void objSetAnimSpeedTo1(int param_1);
extern f32 objFn_801948c0(int obj,int param_2);
extern double FUN_80194a70();
extern undefined4 FUN_8020a568();
extern undefined4 FUN_80247eb8();
extern double SeekTwiceBeforeRead();
extern undefined4 FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028fa2c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c68();
extern int fn_80296240(int obj);
extern int fn_80296448(int obj);
extern undefined4 FUN_80294dc4();
extern void trickyReportError(const char *fmt, ...);
extern void objParticleFn_80099d84(int obj,f32 param_1,int param_4,f32 param_2,int param_5);
extern int objBboxFn_800640cc(Vec *from,Vec *to,f32 radius,int mode,void *hit,int obj,int param_7,
                              int param_8,int param_9,int param_10);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern undefined4 DAT_802c2948;
extern undefined4 DAT_802c294c;
extern undefined4 DAT_802c2950;
extern undefined4 DAT_802c2954;
extern undefined4 DAT_802c2958;
extern undefined4 DAT_802c2970;
extern undefined4 DAT_802c2974;
extern undefined4 DAT_802c2978;
extern undefined4 DAT_802c297c;
extern undefined4 DAT_802c2980;
extern undefined4 DAT_802c2984;
extern undefined4 DAT_802c2988;
extern undefined4 DAT_802c298c;
extern u32 lbl_802C21F0[4];
extern undefined4 DAT_8031df38;
extern undefined4 DAT_8031df50;
extern char lbl_8031D2E8[];
extern char lbl_8031D300[];
extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern undefined4 DAT_803dc8a8;
extern undefined4 DAT_803dc8b0;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de6c8;
extern undefined4* DAT_803de6d0;
extern undefined4 DAT_803de6d4;
extern undefined4 DAT_803e3050;
extern undefined4 DAT_803e3054;
extern undefined4 DAT_803e3058;
extern undefined4 DAT_803e31e8;
extern undefined4 DAT_803e31ec;
extern undefined4 DAT_803e31f0;
extern undefined4 DAT_803e31f4;
extern undefined4 DAT_803e31f8;
extern char sSidekickCommandDebugTextBlock[];
extern undefined4 lbl_803DDA48;
extern int lbl_803DDA54;
extern MapEventInterface **gMapEventInterface;
extern undefined4 lbl_803DBC40;
extern undefined4 lbl_803DBC48;
extern f64 DOUBLE_803e30f0;
extern f64 DOUBLE_803e3218;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u16 lbl_803E23C0;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E24B8;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f64 lbl_803E2460;
extern f32 lbl_803E247C;
extern f32 lbl_803E2524;
extern f32 lbl_803E253C;
extern f32 lbl_803E2540;
extern u32 lbl_803E2558;
extern u32 lbl_803E255C;
extern u32 lbl_803E2560;
extern u32 lbl_803E2564;
extern u16 lbl_803E2568;
extern f32 lbl_803E2574;
extern f32 lbl_803E2570;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E256C;
extern f32 lbl_803E2598;
extern f32 lbl_803E25A0;
extern f32 lbl_803E25A8;
extern f32 lbl_803E25AC;
extern f32 lbl_803E25B0;
extern f32 lbl_803E25B4;
extern f32 lbl_803E25B8;
extern f32 lbl_803E25BC;
extern f32 lbl_803E25C0;
extern f32 lbl_803E25C4;
extern f32 lbl_803E25C8;
extern f32 lbl_803E306C;
extern f32 lbl_803E3078;
extern f32 lbl_803E307C;
extern f32 lbl_803E3098;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30CC;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30E4;
extern f32 lbl_803E310C;
extern f32 lbl_803E3138;
extern f32 lbl_803E3148;
extern f32 lbl_803E3158;
extern f32 lbl_803E3168;
extern f32 lbl_803E317C;
extern f32 lbl_803E3188;
extern f32 lbl_803E3190;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 lbl_803E31CC;
extern f32 lbl_803E31D0;
extern f32 lbl_803E31D4;
extern f32 lbl_803E31D8;
extern f32 lbl_803E31DC;
extern f32 lbl_803E31E0;
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E320C;
extern f32 lbl_803E3210;
extern f32 lbl_803E3220;
extern f32 lbl_803E3224;
extern f32 lbl_803E3228;
extern f32 lbl_803E322C;
extern f32 lbl_803E3234;
extern f32 lbl_803E3238;
extern f32 lbl_803E323C;
extern f32 lbl_803E3240;
extern f32 lbl_803E3244;
extern f32 lbl_803E3250;
extern f32 lbl_803E3254;

/*
 * --INFO--
 *
 * Function: FUN_80144e40
 * EN v1.0 Address: 0x80144E40
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x80144ED8
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80144e40(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  bool bVar4;
  uint uVar3;
  int local_18 [3];
  
  *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) - lbl_803DC074;
  if (*(float *)(param_2 + 0x720) < lbl_803E306C) {
    *(float *)(param_2 + 0x720) = lbl_803E306C;
  }
  iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (((iVar2 != 0) && (*(int *)(local_18[0] + 0xc4) != 0)) &&
     (*(short *)(*(int *)(local_18[0] + 0xc4) + 0x44) == 1)) {
    fVar1 = *(float *)(param_2 + 0x720);
    if (lbl_803E306C < fVar1) {
      *(float *)(param_2 + 0x720) = fVar1 + lbl_803E30D0;
      if (*(char *)(param_2 + 10) != '\v') {
        if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
          iVar2 = *(int *)&((GameObject *)param_1)->extra;
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < ((GameObject *)param_1)->anim.currentMove || (((GameObject *)param_1)->anim.currentMove < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
          *(undefined *)(param_2 + 10) = 10;
          *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        }
        else if (*(float *)(param_2 + 0x720) <= lbl_803E31C4) {
          iVar2 = *(int *)&((GameObject *)param_1)->extra;
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < ((GameObject *)param_1)->anim.currentMove || (((GameObject *)param_1)->anim.currentMove < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
        else {
          *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) * lbl_803E3138;
          uVar3 = FUN_80017690(0x245);
          if (uVar3 != 0) {
            if (lbl_803E306C == *(float *)(param_2 + 0x2ac)) {
              bVar4 = false;
            }
            else if (lbl_803E30A0 == *(float *)(param_2 + 0x2b0)) {
              bVar4 = true;
            }
            else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= lbl_803E30A4) {
              bVar4 = false;
            }
            else {
              bVar4 = true;
            }
            if (!bVar4) {
              *(undefined *)(param_2 + 10) = 0xb;
              return;
            }
          }
          iVar2 = *(int *)&((GameObject *)param_1)->extra;
          if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < ((GameObject *)param_1)->anim.currentMove || (((GameObject *)param_1)->anim.currentMove < 0x29)) &&
              (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)))) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
      }
    }
    else {
      *(float *)(param_2 + 0x720) = fVar1 + lbl_803E317C;
      iVar2 = *(int *)&((GameObject *)param_1)->extra;
      if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < ((GameObject *)param_1)->anim.currentMove || (((GameObject *)param_1)->anim.currentMove < 0x29)))) &&
         (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
        FUN_80039468(param_1,iVar2 + 0x3a8,0x34f,0x500,0xffffffff,0);
      }
    }
  }
  return;
}


/*
 * --INFO--
 *
 * Function: tricky_SeqFn
 * EN v1.0 Address: 0x80145304
 * EN v1.0 Size: 1168b
 * EN v1.1 Address: 0x8014568C
 * EN v1.1 Size: 1328b
 */
typedef struct {
  u8 bit7 : 1;
  u8 bit6 : 1;
  u8 bit5 : 1;
  u8 rest : 5;
} TrickyByteFlags;

extern void Sfx_StopObjectChannel(int obj,int channel);
extern int Sfx_AddLoopedObjectSound(int obj,int sfxId);
extern void mapBlockFn_80059c2c(u8 *outFlags);
extern int ObjModel_ClearBlendChannels(int model);
extern void characterDoEyeAnims(int obj,void *p);
extern int fn_80138D7C(int obj,int state);
extern void Tricky_updateBlendChannelWeight(int obj,int state);
extern ObjectTriggerInterface **gObjectTriggerInterface;

int tricky_SeqFn(int obj,int unused,ObjAnimUpdateState *animUpdate)
{
  int state;
  int i;
  int j;
  int slot;
  int setup;
  bool playing;
  u8 blockFlags[120];

  state = *(int *)&((GameObject *)obj)->extra;
  if ((((TrickyState *)state)->unk54 & 0x200) == 0) {
    ObjHits_DisableObject(obj);
    Sfx_StopObjectChannel(obj,0x7f);
    if ((((TrickyState *)state)->unk54 & 0x800) != 0) {
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffff7ff;
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x1000;
      i = 0;
      slot = state;
      do {
        objSetAnimSpeedTo1(*(int *)(slot + 0x700));
        slot = slot + 4;
        i = i + 1;
      } while (i < 7);
      Sfx_RemoveLoopedObjectSound(obj,0x3dc);
      slot = *(int *)&((GameObject *)obj)->extra;
      if ((((TrickyByteFlags *)(slot + 0x58))->bit6 == 0) &&
         (((((GameObject *)obj)->anim.currentMove >= 0x30 || (((GameObject *)obj)->anim.currentMove < 0x29)) &&
          (playing = Sfx_IsPlayingFromObjectChannel(obj,0x10), !playing)))) {
        objAudioFn_800393f8(obj,(void *)(slot + 0x3a8),0x29d,0,0xffffffff,0);
      }
    }
    Sfx_RemoveLoopedObjectSound(obj,0x13d);
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x200;
    if ((animUpdate->hitVolumePair & 3) == 0) {
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x4000;
    }
    if (((TrickyByteFlags *)&((TrickyState *)state)->unk82E)->bit5 == 0) {
      ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
      ((TrickyByteFlags *)&((TrickyState *)state)->unk82E)->bit6 = 0;
    }
  }
  for (i = 0; i < animUpdate->eventCount; i++) {
    switch (animUpdate->eventIds[i]) {
    case 1:
      if ((((TrickyState *)state)->unk54 & 0x800) != 0) {
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffff7ff;
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x1000;
        j = 0;
        slot = state;
        do {
          objSetAnimSpeedTo1(*(int *)(slot + 0x700));
          slot = slot + 4;
          j = j + 1;
        } while (j < 7);
        Sfx_RemoveLoopedObjectSound(obj,0x3dc);
        slot = *(int *)&((GameObject *)obj)->extra;
        if ((((TrickyByteFlags *)(slot + 0x58))->bit6 == 0) &&
           (((((GameObject *)obj)->anim.currentMove >= 0x30 || (((GameObject *)obj)->anim.currentMove < 0x29)) &&
            (playing = Sfx_IsPlayingFromObjectChannel(obj,0x10), !playing)))) {
          objAudioFn_800393f8(obj,(void *)(slot + 0x3a8),0x29d,0,0xffffffff,0);
        }
      } else if (Obj_IsLoadingLocked()) {
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x800;
        j = 0;
        slot = state;
        do {
          setup = Obj_AllocObjectSetup(0x24,0x4f0);
          *(u8 *)(setup + 4) = 2;
          *(u8 *)(setup + 5) = 1;
          *(s16 *)(setup + 0x1a) = j;
          *(int *)(slot + 0x700) = Obj_SetupObject(setup,5,((GameObject *)obj)->anim.mapEventSlot,-1,*(int *)&((GameObject *)obj)->anim.parent);
          slot = slot + 4;
          j = j + 1;
        } while (j < 7);
        Sfx_PlayFromObject(obj,0x3db);
        Sfx_AddLoopedObjectSound(obj,0x3dc);
      }
      break;
    case 2:
      GameBit_Set(0x186,1);
      if ((GameBit_Get(0x186) != 0 && *(void **)&((TrickyState *)state)->unk7CC == NULL) && Obj_IsLoadingLocked()) {
        mapBlockFn_80059c2c(blockFlags);
        if (blockFlags[0xd] != 0) {
          setup = Obj_AllocObjectSetup(0x20,0x244);
        } else {
          setup = Obj_AllocObjectSetup(0x20,0x254);
        }
        *(int *)&((TrickyState *)state)->unk7CC = Obj_SetupObject(setup,4,-1,-1,*(int *)&((GameObject *)obj)->anim.parent);
        ObjLink_AttachChild(obj,*(int *)&((TrickyState *)state)->unk7CC,3);
      }
      break;
    case 3:
      **(u8 **)&((TrickyState *)state)->progressPtr = ((TrickyState *)state)->unk82D;
      break;
    case 0x2b:
      ((GameObject *)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
      break;
    case 0x2c:
      ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
      break;
    }
  }
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7A8);
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7B0);
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7B8);
  fn_80138D7C(obj,state);
  Tricky_updateBlendChannelWeight(obj,state);
  objAudioFn_8006ef38(obj,(int)&animUpdate->animEvents,1,state + 0x7d8,state + 0xf8,lbl_803E23E8,lbl_803E23E8);
  if ((((TrickyState *)state)->unk54 & 1) != 0) {
    animUpdate->hitVolumePair &= ~0x40;
    characterDoEyeAnims(obj,(void *)(state + 0x378));
    return (*gObjectTriggerInterface)->func20((void *)obj,(u8 *)animUpdate,1,0xf,0x1e,0,0);
  }
  return 0;
}


/*
 * --INFO--
 *
 * Function: sideCommandEnable
 * EN v1.0 Address: 0x801459E0
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80145E08
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sideCommandEnable(int obj,int targetObj,int commandKind,int commandType)
{
  int commandCount;
  int commandEntry;
  int commandIndex;
  int state;
  
  state = *(int *)&((GameObject *)obj)->extra;
  if (((TrickyState *)state)->unk798 == 10) {
    trickyReportError(sSidekickCommandDebugTextBlock);
    return;
  }
  ((TrickyState *)state)->unk0B = (byte)(((TrickyState *)state)->unk0B | (1 << commandType));
  commandIndex = 0;
  commandEntry = state;
  for (commandCount = (uint)((TrickyState *)state)->unk798; 0 < commandCount;
       commandCount = commandCount - 1) {
    if (*(uint *)(commandEntry + 0x748) == (uint)targetObj) {
      commandEntry = state + commandIndex * 8;
      *(undefined *)(commandEntry + 0x74e) = 3;
      return;
    }
    commandEntry = commandEntry + 8;
    commandIndex = commandIndex + 1;
  }
  commandEntry = state + (uint)((TrickyState *)state)->unk798 * 8;
  *(int *)(commandEntry + 0x748) = targetObj;
  commandKind = (s8)commandKind;
  commandEntry = state + (uint)((TrickyState *)state)->unk798 * 8;
  *(char *)(commandEntry + 0x74c) = (char)commandKind;
  commandType = (s8)commandType;
  commandEntry = state + (uint)((TrickyState *)state)->unk798 * 8;
  *(char *)(commandEntry + 0x74d) = (char)commandType;
  commandEntry = state + (uint)((TrickyState *)state)->unk798 * 8;
  *(undefined *)(commandEntry + 0x74e) = 3;
  *(char *)&((TrickyState *)state)->unk798 = *(char *)&((TrickyState *)state)->unk798 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: Tricky_updateSideCommandPrompts
 * EN v1.0 Address: 0x80145AE8
 * EN v1.0 Size: 1648b
 * EN v1.1 Address: 0x80145F10
 * EN v1.1 Size: 1648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int Tricky_updateSideCommandPrompts(int obj)
{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  uint commandMask;
  int iVar8;
  bool bVar11;
  undefined2 *puVar9;
  undefined4 uVar10;
  byte bVar12;
  int iVar13;
  char local_38 [4];
  char local_34 [4];
  undefined4 local_30 [12];
  
  iVar6 = obj;
  iVar13 = *(int *)(iVar6 + 0xb8);
  bVar11 = false;
  bVar3 = false;
  bVar4 = false;
  bVar5 = false;
  local_30[0] = DAT_803e3058;
  uVar7 = GameBit_Get(0x4e4);
  if (uVar7 != 0) {
    commandMask = *(byte *)(iVar13 + 0xb) | 9;
    if ((*(uint *)(iVar13 + 0x54) & 0x10) != 0) {
      *(undefined *)(iVar13 + 0xb) = 0;
    }
    if (((*(byte *)(iVar13 + 8) == 8) || (*(byte *)(iVar13 + 8) == 0xd)) ||
       ((*(byte *)(iVar13 + 8) == 0xe && (*(byte *)(iVar13 + 10) == 1)))) {
      bVar3 = true;
      commandMask |= 0x10;
    }
    else {
      iVar8 = trickyFindNearestUsableBaddie(*(int *)(iVar13 + 4),1,lbl_803E2524);
      if (iVar8 != 0) {
        bVar3 = true;
        bVar5 = true;
      }
    }
    if (*(char *)(iVar13 + 0xb) != '\0') {
      for (bVar12 = 0; bVar12 < *(byte *)(iVar13 + 0x798); bVar12 = bVar12 + 1) {
        iVar8 = iVar13 + (uint)bVar12 * 8;
        cVar1 = *(char *)(iVar8 + 0x74c);
        if (cVar1 == '\0') {
          if (*(short *)(*(int *)(iVar8 + 0x748) + 0x46) == 0x6a) {
            bVar4 = true;
          }
          bVar3 = true;
        }
        else if (cVar1 == '\x01') {
          bVar11 = true;
        }
      }
    }
    if (((*(uint *)(iVar13 + 0x54) & 0x10) == 0) && (uVar7 = GameBit_Get(0x3f8), uVar7 != 0)) {
      iVar8 = Obj_GetPlayerObject();
      iVar8 = fn_80296240(iVar8);
      if ((iVar8 != 0) && (uVar7 = GameBit_Get(0xd00), uVar7 == 0)) {
        if (fn_80296448(*(int *)(iVar13 + 4)) == 0) {
          commandMask |= 0x20;
        }
      }
    }
    if (GameBit_Get(0xdd) == 0) {
      commandMask &= ~1;
    }
    if (GameBit_Get(0x9e) == 0) {
      commandMask &= ~2;
    }
    if (GameBit_Get(0x245) == 0) {
      commandMask &= ~0x10;
    }
    *(undefined *)(iVar13 + 0xb) = 0;
    if ((bVar11) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7b4) = lbl_803E3188;
      if ((*(int *)(iVar13 + 0x7b0) == 0) && (Obj_IsLoadingLocked() != 0)) {
        uVar7 = randomGetRange(0,1);
        uVar2 = *(ushort *)((int)local_30 + uVar7 * 2);
        iVar8 = *(int *)(iVar6 + 0xb8);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
            (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
          objAudioFn_800393f8(iVar6,(void *)(iVar8 + 0x3a8),uVar2,0x500,0xffffffff,0);
        }
        puVar9 = (undefined2 *)Obj_AllocObjectSetup(0x20,0x17c);
        local_34[0] = -1;
        local_34[1] = -1;
        local_34[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_34[0] == -1) {
          uVar7 = 0;
        }
        else if (local_34[1] == -1) {
          uVar7 = 1;
        }
        else if (local_34[2] == -1) {
          uVar7 = 2;
        }
        else if (local_34[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) =
             (byte)((uVar7 & 0xff) << 4) & 0x30 | *(byte *)(iVar13 + 0x7bc) & 0xcf;
        uVar10 = Obj_SetupObject((int)puVar9,4,0xff,0xffffffff,*(int *)(iVar6 + 0x30));
        *(undefined4 *)(iVar13 + 0x7b0) = uVar10;
        ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7b0),*(byte *)(iVar13 + 0x7bc) >> 4 & 3);
      }
    }
    else if (*(int *)(iVar13 + 0x7b0) != 0) {
      *(float *)(iVar13 + 0x7b4) = *(float *)(iVar13 + 0x7b4) - lbl_803DC074;
      if ((double)*(float *)(iVar13 + 0x7b4) <= (double)lbl_803E306C) {
        objAnimFreeChildren(iVar6,iVar13,(int *)(iVar13 + 0x7b0));
      }
    }
    if ((bVar3) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7ac) = lbl_803E3188;
      if ((*(int *)(iVar13 + 0x7a8) == 0) && (Obj_IsLoadingLocked() != 0)) {
        uVar7 = randomGetRange(0,3);
        if (uVar7 == 0) {
          if (bVar4) {
            iVar8 = *(int *)(iVar6 + 0xb8);
            if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
                (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
              objAudioFn_800393f8(iVar6,(void *)(iVar8 + 0x3a8),0x359,0x500,0xffffffff,0);
            }
          }
          else if ((((bVar5) &&
                    (iVar8 = *(int *)(iVar6 + 0xb8), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
                   ((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)))) &&
                  (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)) {
            objAudioFn_800393f8(iVar6,(void *)(iVar8 + 0x3a8),0x358,0x500,0xffffffff,0);
          }
        }
        puVar9 = (undefined2 *)Obj_AllocObjectSetup(0x20,0x175);
        local_38[0] = -1;
        local_38[1] = -1;
        local_38[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_38[0] == -1) {
          uVar7 = 0;
        }
        else if (local_38[1] == -1) {
          uVar7 = 1;
        }
        else if (local_38[2] == -1) {
          uVar7 = 2;
        }
        else if (local_38[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) = (byte)((uVar7 & 0xff) << 6) | *(byte *)(iVar13 + 0x7bc) & 0x3f;
        uVar10 = Obj_SetupObject((int)puVar9,4,0xff,0xffffffff,*(int *)(iVar6 + 0x30));
        *(undefined4 *)(iVar13 + 0x7a8) = uVar10;
        ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7a8),(ushort)(*(byte *)(iVar13 + 0x7bc) >> 6));
      }
    }
    else if (*(int *)(iVar13 + 0x7a8) != 0) {
      *(float *)(iVar13 + 0x7ac) = *(float *)(iVar13 + 0x7ac) - lbl_803DC074;
      if ((double)*(float *)(iVar13 + 0x7ac) <= (double)lbl_803E306C) {
        objAnimFreeChildren(iVar6,iVar13,(int *)(iVar13 + 0x7a8));
      }
    }
    return commandMask;
  }
  return -1;
}


/*
 * --INFO--
 *
 * Function: Tricky_destroy
 * EN v1.0 Address: 0x801461DC
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80146604
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Tricky_destroy(int obj,int shouldKeepFlameChildren)
{
  bool bVar1;
  int state;
  int i;
  int childSlot;

  state = *(int *)&((GameObject *)obj)->extra;
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[0]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[1]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[2]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[3]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[4]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[5]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[6]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[7]);
  freeAndNull((void *)((TrickyState *)state)->voxBlocks[8]);
  ObjGroup_RemoveObject(obj,1);
  (*gExpgfxInterface)->freeSource((u32)obj);
  if ((shouldKeepFlameChildren == 0) && ((((TrickyState *)state)->unk54 & 0x800) != 0)) {
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffff7ff;
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x1000;
    i = 0;
    childSlot = state;
    do {
      objSetAnimSpeedTo1(*(int *)(childSlot + 0x700));
      childSlot = childSlot + 4;
      i = i + 1;
    } while (i < 7);
    Sfx_RemoveLoopedObjectSound(obj,0x3dc);
    childSlot = *(int *)&((GameObject *)obj)->extra;
    if (((*(byte *)(childSlot + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < ((GameObject *)obj)->anim.currentMove || (((GameObject *)obj)->anim.currentMove < 0x29)) &&
        (bVar1 = Sfx_IsPlayingFromObjectChannel(obj,0x10), !bVar1)))) {
      objAudioFn_800393f8(obj,(void *)(childSlot + 0x3a8),0x29d,0,0xffffffff,0);
    }
  }
  doNothing_onTrickyFree();
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7A8);
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7B0);
  objAnimFreeChildren(obj,state,(int *)&((TrickyState *)state)->unk7B8);
  if (*(int *)&((TrickyState *)state)->unk7CC != 0) {
    ObjLink_DetachChild(obj,*(int *)&((TrickyState *)state)->unk7CC);
    Obj_FreeObject(*(int *)&((TrickyState *)state)->unk7CC);
  }
  if (((((TrickyState *)state)->unk58 >> 7 & 1) != 0) && (lbl_803DDA48 != 0)) {
    Obj_FreeObject(lbl_803DDA48);
    lbl_803DDA48 = 0;
  }
  return;
}

/* Tricky_update: 8672b - Tricky sidekick command state machine and per-frame update. */
typedef struct {
  u8 slotA : 2;
  u8 slotB : 2;
  u8 slotC : 2;
  u8 slotD : 2;
} TrickySlotBits;

typedef struct {
  void *pad[9];
  void (*handlers[1])(int obj, int state);
} TrickyHandlerTable;

typedef struct {
  int a;
  int b;
  int c;
  int d;
  int e;
} TrickyCmdQuery;

typedef struct {
  u16 a;
  u16 b;
} TrickySfxPair;

extern int lbl_802C21C8[];
extern TrickySfxPair lbl_803E23C4;
extern f32 lbl_803E2408;
extern f32 lbl_803E23EC;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24D8;
extern f32 lbl_803E2538;
extern f32 lbl_803E2544;
extern f32 lbl_803E2548;
extern f32 lbl_803E254C;
extern f32 lbl_803E2550;
extern int trickySelectQueuedCommandTarget(int state, int type);
void trickyDebugPrint(const char *fmt, ...);
extern int trickyFoodFn_8013db3c(int obj, int state);
extern void memmove(void *dst, void *src, int n);
extern void fn_801B17F4(void);
extern void fn_801B6D40(void);
extern void fn_801FD4A8(void);
extern void fn_801B0784(void);
extern void drchimmey_countdownCallback(void);
extern void fn_801DA9CC(void);
extern void wcbeacon_aButtonCallback(void);
extern void fn_8003A168(int obj, void *p);
extern void fn_8003B228(int obj, void *p);
extern void fn_8003A230(int obj, void *p, f32 f);

#define TRICKY_RESET_COMMAND(state) \
  *(u8 *)((state) + 8) = 1; \
  *(u8 *)((state) + 0xa) = 0; \
  z = lbl_803E23DC; \
  *(f32 *)((state) + 0x71c) = z; \
  *(f32 *)((state) + 0x720) = z; \
  *(uint *)((state) + 0x54) = *(uint *)((state) + 0x54) & ~0x10LL; \
  *(uint *)((state) + 0x54) = *(uint *)((state) + 0x54) & ~0x10000LL; \
  *(uint *)((state) + 0x54) = *(uint *)((state) + 0x54) & ~0x20000LL; \
  *(uint *)((state) + 0x54) = *(uint *)((state) + 0x54) & ~0x40000LL; \
  *(s8 *)((state) + 0xd) = -1

#define TRICKY_VOICE(obj, st, sfx, vol) \
  st = *(int *)((obj) + 0xb8); \
  if ((((TrickyByteFlags *)(st + 0x58))->bit6 == 0) && \
     (((*(short *)((obj) + 0xa0) >= 0x30 || (*(short *)((obj) + 0xa0) < 0x29)) && \
      (playing = Sfx_IsPlayingFromObjectChannel((obj), 0x10), !playing)))) { \
    objAudioFn_800393f8((obj), (void *)(st + 0x3a8), (sfx), (vol), 0xffffffff, 0); \
  }

#define TRICKY_SPAWN_BUBBLE(obj, state) \
  if (*(void **)((state) + 0x7b8) == NULL) { \
    int setup_; \
    s8 used_[4]; \
    int slot_; \
    setup_ = Obj_AllocObjectSetup(0x20, 0x17b); \
    used_[0] = -1; \
    used_[1] = -1; \
    used_[2] = -1; \
    if (*(void **)((state) + 0x7a8) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotA] = 1; \
    } \
    if (*(void **)((state) + 0x7b0) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotB] = 1; \
    } \
    if (*(void **)((state) + 0x7b8) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotC] = 1; \
    } \
    if (used_[0] == -1) { slot_ = 0; } \
    else if (used_[1] == -1) { slot_ = 1; } \
    else if (used_[2] == -1) { slot_ = 2; } \
    else if (used_[3] == -1) { slot_ = 3; } \
    else { slot_ = -1; } \
    ((TrickySlotBits *)((state) + 0x7bc))->slotC = (u8)slot_; \
    *(int *)((state) + 0x7b8) = Obj_SetupObject(setup_, 4, -1, -1, *(int *)((obj) + 0x30)); \
    ObjLink_AttachChild((obj), *(int *)((state) + 0x7b8), ((TrickySlotBits *)((state) + 0x7bc))->slotC); \
    z = lbl_803E23DC; \
    *(f32 *)((state) + 0x7c0) = z; \
    *(f32 *)((state) + 0x7c4) = z; \
    *(f32 *)((state) + 0x7c8) = z; \
  }

void Tricky_update(int obj)
{
  char *base;
  int state;
  int found;
  int p;
  int cmd;
  int st;
  TrickyState *stState;
  bool playing;
  int i;
  int setup;
  int count;
  uint f;
  int diff;
  int step;
  int played;
  int talking;
  int sfx2;
  u16 sfxId;
  u32 target;
  f32 z;
  s8 flagsByte;
  u8 blockFlags[120];
  TrickyCmdQuery cmdQuery;
  TrickySfxPair pair;

  base = (char *)lbl_8031D2E8;
  state = *(int *)&((GameObject *)obj)->extra;
  found = 0;
  cmdQuery = *(TrickyCmdQuery *)lbl_802C21C8;
  pair = lbl_803E23C4;
  walkgroupFindExitPointFn_800dc398();
  if (GameBit_Get(0x186) != 0 && *(void **)&((TrickyState *)state)->unk7CC == NULL && Obj_IsLoadingLocked()) {
    mapBlockFn_80059c2c(blockFlags);
    if (blockFlags[0xd] != 0) {
      setup = Obj_AllocObjectSetup(0x20,0x244);
    } else {
      setup = Obj_AllocObjectSetup(0x20,0x254);
    }
    *(int *)&((TrickyState *)state)->unk7CC = Obj_SetupObject(setup,4,-1,-1,*(int *)&((GameObject *)obj)->anim.parent);
    ObjLink_AttachChild(obj,*(int *)&((TrickyState *)state)->unk7CC,3);
  }
  if ((((TrickyState *)state)->unk54 & 0x40000000) != 0) {
    p = *(int *)state;
    if (*(u8 *)p == *(u8 *)(p + 1)) {
      TRICKY_VOICE(obj, st, 0x364, 0x500);
    } else {
      TRICKY_VOICE(obj, st, 0x363, 0x500);
    }
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xbfffffff;
  }
  flagsByte = ((TrickyState *)state)->unk358;
  trickyDebugPrint(base + 0x894,flagsByte & 1,flagsByte & 2,flagsByte & 4,flagsByte & 8,
                   flagsByte & 0x10,flagsByte & 0x20,flagsByte & 0x40,flagsByte & 0x80);
  p = *(int *)state;
  trickyDebugPrint(base + 0x8b4,*(u8 *)p,*(u8 *)(p + 1));
  if ((((TrickyState *)state)->unk54 & 0x200) != 0) {
    ObjHits_EnableObject(obj);
    if ((((TrickyState *)state)->unk54 & 0x4000) == 0) {
      TRICKY_RESET_COMMAND(state);
      ((TrickyState *)state)->unk09 = 0;
      ((TrickyState *)state)->unk10 = z;
      ((TrickyState *)state)->unk14 = z;
      ((TrickyState *)state)->homePosX = ((GameObject *)obj)->anim.worldPosX;
      ((TrickyState *)state)->homePosY = ((GameObject *)obj)->anim.worldPosY;
      ((TrickyState *)state)->homePosZ = ((GameObject *)obj)->anim.worldPosZ;
      (*gPathControlInterface)->attachObject((void *)obj,
                                             &((TrickyState *)state)->pathControlFlags);
      if (((GameObject *)obj)->anim.currentMove == 8 || ((GameObject *)obj)->anim.currentMove == 7) {
        ((TrickyState *)state)->unk2AC = lbl_803E2414;
        ((TrickyState *)state)->unk2B0 = lbl_803E2544;
      } else {
        ((TrickyState *)state)->unk2AC = lbl_803E23DC;
      }
    }
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xffffbdfe;
    if (((TrickyByteFlags *)&((TrickyState *)state)->unk82E)->bit5 != 0) {
      ((TrickyByteFlags *)&((TrickyState *)state)->unk82E)->bit5 = 0;
    } else {
      ((TrickyByteFlags *)&((TrickyState *)state)->unk82E)->bit7 = 1;
    }
  }
  if (*(void **)&((TrickyState *)state)->unk24 != NULL && (*(u16 *)(*(int *)&((TrickyState *)state)->unk24 + 0xb0) & 0x40) != 0) {
    if ((((TrickyState *)state)->unk54 & 0x10) != 0) {
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & ~0x10LL;
      ((TrickyState *)state)->unk374 = 2;
      (*gPathControlInterface)->attachObject((void *)obj,
                                             &((TrickyState *)state)->pathControlFlags);
      ((GameObject *)obj)->anim.localPosX = ((TrickyState *)state)->homePosX;
      ((GameObject *)obj)->anim.localPosY = ((TrickyState *)state)->homePosY;
      ((GameObject *)obj)->anim.localPosZ = ((TrickyState *)state)->homePosZ;
      ((GameObject *)obj)->anim.worldPosX = ((TrickyState *)state)->homePosX;
      ((GameObject *)obj)->anim.worldPosY = ((TrickyState *)state)->homePosY;
      ((GameObject *)obj)->anim.worldPosZ = ((TrickyState *)state)->homePosZ;
      ObjHits_SyncObjectPosition(obj);
      i = 0;
      ((TrickyState *)state)->unk09 = i;
      z = lbl_803E23DC;
      ((TrickyState *)state)->unk10 = z;
      ((TrickyState *)state)->unk14 = z;
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x80000;
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xffffdfff;
      if ((((TrickyState *)state)->unk54 & 0x800) != 0) {
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffff7ff;
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x1000;
        p = state;
        do {
          objSetAnimSpeedTo1(*(int *)(p + 0x700));
          p = p + 4;
          i = i + 1;
        } while (i < 7);
        Sfx_RemoveLoopedObjectSound(obj,0x3dc);
        TRICKY_VOICE(obj, st, 0x29d, 0);
      }
      Sfx_RemoveLoopedObjectSound(obj,0x13d);
    }
    TRICKY_RESET_COMMAND(state);
    *(int *)&((TrickyState *)state)->unk24 = 0;
  }
  if ((((TrickyState *)state)->unk54 & 0x10) != 0 &&
      (*gGameUIInterface)->isEventReady(0xc1) != 0) {
    cmd = 0;
  } else {
    cmd = (*gGameUIInterface)->isOneOfItemsBeingUsed((s32 *)&cmdQuery, 5);
  }
  p = state;
  count = ((TrickyState *)state)->unk798;
  for (i = 0; i < count; i++) {
    if (*(s8 *)(p + 0x74d) == cmd) {
      found = 1;
      break;
    }
    p = p + 8;
  }
  if ((((TrickyState *)state)->unk54 & 0x10) == 0 && trickyFoodFn_8013db3c(obj,state) == 2) {
    ((TrickyState *)state)->unk08 = 0x11;
  } else if (((TrickyState *)state)->unk08 == 8 && cmd == 4) {
    *(u8 *)&((TrickyState *)state)->unk734 = *(u8 *)&((TrickyState *)state)->unk734 ^ 1;
  } else if (((TrickyState *)state)->unk08 == 0xd && cmd == 4 && found == 0) {
    *(int *)&((TrickyState *)state)->unk728 = 1;
  } else if (((TrickyState *)state)->unk08 == 0xe && cmd == 4) {
    *(int *)&((TrickyState *)state)->unk728 = 1;
  } else if (cmd == 0) {
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x30002;
  } else {
    f = ((TrickyState *)state)->unk54;
    if ((f & 0x10) == 0) {
      switch (cmd) {
      case 1:
        ((TrickyState *)state)->unkD = 1;
        trickySelectQueuedCommandTarget(state,1);
        TRICKY_VOICE(obj, st, 0x13c, 0);
        switch (*(s16 *)(*(int *)&((TrickyState *)state)->unk24 + 0x46)) {
        case 0x1ca:
          if (**(u8 **)state < 4) {
            if (Obj_IsLoadingLocked()) {
              ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 4;
              TRICKY_RESET_COMMAND(state);
              TRICKY_SPAWN_BUBBLE(obj, state);
            }
          } else {
            ((TrickyState *)state)->unk08 = 2;
          }
          break;
        case 0x160:
          if (**(u8 **)state < 4) {
            if (Obj_IsLoadingLocked()) {
              ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 4;
              TRICKY_RESET_COMMAND(state);
              TRICKY_SPAWN_BUBBLE(obj, state);
            }
          } else {
            ((TrickyState *)state)->unk08 = 3;
          }
          break;
        case 0x6a:
        case 0x193:
        case 0x3fb:
        case 0x658:
          ((TrickyState *)state)->unk08 = 9;
          break;
        case 0x195:
          if (**(u8 **)state < 2) {
            if (Obj_IsLoadingLocked()) {
              ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 4;
              TRICKY_RESET_COMMAND(state);
              TRICKY_SPAWN_BUBBLE(obj, state);
            }
          } else {
            ((TrickyState *)state)->unk08 = 0x10;
          }
          break;
        case 0x352:
          if (**(u8 **)state < 4) {
            if (Obj_IsLoadingLocked()) {
              ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 4;
              TRICKY_RESET_COMMAND(state);
              TRICKY_SPAWN_BUBBLE(obj, state);
            }
          } else {
            ((TrickyState *)state)->unk08 = 2;
          }
          break;
        case 0x358:
          ((TrickyState *)state)->unk08 = 0xe;
          break;
        default:
          TRICKY_RESET_COMMAND(state);
          trickyReportError(base + 0x8c4);
          break;
        }
        break;
      case 3:
        played = 0;
        if (((TrickyState *)state)->unkD == 3) {
          p = state;
          count = ((TrickyState *)state)->unk798;
          for (i = 0; i < count; i++) {
            if (*(s8 *)(p + 0x74d) == 3) {
              played = 1;
            }
            p = p + 8;
          }
        } else {
          played = 1;
        }
        if (played != 0) {
          ((TrickyState *)state)->unkD = 3;
          if (trickySelectQueuedCommandTarget(state,3) != 0) {
            switch (*(s16 *)(*(int *)&((TrickyState *)state)->unk24 + 0x46)) {
            case 0x36:
            case 0x104:
            case 0x131:
            case 0x19f:
            case 0x26c:
            case 0x475:
            case 0x546:
            case 0x7c3:
              ((TrickyState *)state)->unk08 = 0xa;
              ((TrickyState *)state)->unk740 = (f32)(int)randomGetRange(0x1f4,0x2ee);
              break;
            case 0x6f0:
              ((TrickyState *)state)->unk08 = 0xe;
              break;
            default:
              ((TrickyState *)state)->unk08 = 8;
              break;
            }
          } else {
            ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x40000LL;
          }
        }
        break;
      case 4:
        if (**(u8 **)state < 4) {
          if (Obj_IsLoadingLocked()) {
            ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 4;
            TRICKY_RESET_COMMAND(state);
            TRICKY_SPAWN_BUBBLE(obj, state);
          }
        } else {
          ((TrickyState *)state)->unkD = 4;
          trickySelectQueuedCommandTarget(state,4);
          ((TrickyState *)state)->unk08 = 7;
          switch (*(s16 *)(*(int *)&((TrickyState *)state)->unk24 + 0x46)) {
          case 0x1c9:
            *(void **)&((TrickyState *)state)->unk724 = (void *)fn_801B17F4;
            break;
          case 0x718:
            *(void **)&((TrickyState *)state)->unk724 = (void *)fn_801B6D40;
            break;
          case 0x551:
            *(void **)&((TrickyState *)state)->unk724 = (void *)fn_801FD4A8;
            break;
          case 0x191:
            *(void **)&((TrickyState *)state)->unk724 = (void *)fn_801B0784;
            break;
          case 0x470:
            *(void **)&((TrickyState *)state)->unk724 = (void *)drchimmey_countdownCallback;
            break;
          case 0x102:
          case 0x194:
          case 0x542:
          case 0x54c:
          case 0x6f9:
            *(void **)&((TrickyState *)state)->unk724 = 0;
            break;
          case 0x3c:
            *(void **)&((TrickyState *)state)->unk724 = (void *)fn_801DA9CC;
            break;
          case 0x50f:
            *(void **)&((TrickyState *)state)->unk724 = (void *)wcbeacon_aButtonCallback;
            break;
          default:
            TRICKY_RESET_COMMAND(state);
            trickyReportError(base + 0x8c4);
            break;
          }
        }
        break;
      case 5:
        if (Obj_IsLoadingLocked()) {
          ((TrickyState *)state)->unkD = 5;
          setup = Obj_AllocObjectSetup(0x18,0x112);
          *(u8 *)(setup + 7) = 0xff;
          *(u8 *)(setup + 4) = 2;
          ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.worldPosX;
          ((ObjPlacement *)setup)->posY = ((GameObject *)obj)->anim.worldPosY;
          ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.worldPosZ;
          *(int *)&((TrickyState *)state)->unk24 = Obj_SetupObject(setup,5,-1,-1,*(int *)&((GameObject *)obj)->anim.parent);
          target = *(int *)&((TrickyState *)state)->unk24 + 0x18;
          if (*(u32 *)&((TrickyState *)state)->unk28 != target) {
            *(u32 *)&((TrickyState *)state)->unk28 = target;
            ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffffbff;
            ((TrickyState *)state)->unkD2 = 0;
          }
          ((TrickyState *)state)->unkA = 0;
          ((TrickyState *)state)->unk08 = 0xb;
        }
        break;
      default:
        if (((TrickyState *)state)->unk08 == 1 && ((TrickyState *)state)->unkD != 0 && (f & 0x20000) == 0) {
          step = trickyFindNearestUsableBaddie(((TrickyState *)state)->playerObj,0,lbl_803E24D8);
          if (step != 0) {
            *(int *)&((TrickyState *)state)->unk24 = step;
            if (*(u32 *)&((TrickyState *)state)->unk28 != (u32)(step + 0x18)) {
              *(u32 *)&((TrickyState *)state)->unk28 = step + 0x18;
              ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffffbff;
              ((TrickyState *)state)->unkD2 = 0;
            }
            ((TrickyState *)state)->unk08 = 0xd;
            ((TrickyState *)state)->unkA = 0;
            *(int *)&((TrickyState *)state)->unk728 = 0;
          }
        }
        break;
      }
    } else if (cmd == 3) {
      ((TrickyState *)state)->unk54 = f | 0x40000LL;
    }
  }
  f = ((TrickyState *)state)->unk54;
  if ((f & 0x10) == 0) {
    if ((f & 0x10000) != 0) {
      if ((f & 0x20000) != 0) {
        TRICKY_RESET_COMMAND(state);
        *(u8 *)&((TrickyState *)state)->unkD = 0;
      } else {
        TRICKY_RESET_COMMAND(state);
      }
      ((TrickyState *)state)->unk71C = lbl_803E2548;
    } else if ((f & 0x40000) != 0) {
      *(int *)&((TrickyState *)state)->unk24 = obj;
      ((TrickyState *)state)->unk08 = 0xf;
      ((TrickyState *)state)->unk740 = (f32)(int)randomGetRange(0x1f4,0x2ee);
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & ~0x20000LL;
      ((TrickyState *)state)->unkD = 3;
      if (*(u32 *)&((TrickyState *)state)->unk28 != (u32)&((TrickyState *)state)->unk72C) {
        *(u32 *)&((TrickyState *)state)->unk28 = (u32)&((TrickyState *)state)->unk72C;
        ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffffbff;
        ((TrickyState *)state)->unkD2 = 0;
      }
    }
  }
  *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
  ((TrickyState *)state)->unk353 = 1;
  ((TrickyHandlerTable *)base)->handlers[((TrickyState *)state)->unk08](obj,state);
  ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffffffd;
  ((TrickyState *)state)->unk18 += timeDelta;
  if (((TrickyState *)state)->unk18 > lbl_803E247C) {
    if (((GameObject *)obj)->anim.currentMove != ((TrickyState *)state)->unk20) {
      if ((((TrickyState *)state)->unk50 & 0x1000000) != 0 && (((TrickyState *)state)->unk54 & 0x1000000) != 0) {
        ObjAnim_SetCurrentMove(obj,((TrickyState *)state)->unk20,((GameObject *)obj)->anim.currentMoveProgress,0);
      } else {
        ObjAnim_SetCurrentMove(obj,((TrickyState *)state)->unk20,lbl_803E23DC,0);
      }
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xf9fffe1f;
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | ((TrickyState *)state)->unk50;
      ((TrickyState *)state)->unk18 = lbl_803E23DC;
      ((TrickyState *)state)->unk34 = ((TrickyState *)state)->unk38;
    }
  }
  if ((((TrickyState *)state)->unk54 & 0x2000000) != 0) {
    ((GameObject *)obj)->anim.localPosX += timeDelta * (((TrickyState *)state)->unk2C * ((TrickyState *)state)->unk14);
    ((GameObject *)obj)->anim.localPosZ += timeDelta * (((TrickyState *)state)->unk30 * ((TrickyState *)state)->unk14);
    ObjAnim_SampleRootCurvePhase(((TrickyState *)state)->unk14,(ObjAnimComponent *)obj,(float *)(state + 0x34));
  }
  if (((TrickyState *)state)->unk34 == lbl_803E23DC) {
    ObjAnim_SetMoveProgress(((TrickyState *)state)->unk3C,(ObjAnimComponent *)obj);
  }
  if (((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj,((TrickyState *)state)->unk34,timeDelta,(void *)(state + 0x80c)) != 0) {
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x8000000;
  } else {
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xf7ffffff;
  }
  if ((((TrickyState *)state)->unk54 & 0x100) != 0) {
    diff = ((TrickyState *)state)->unk5A - (u16)*(s16 *)obj;
    if (diff > 0x8000) {
      diff -= 0xffff;
    }
    if (diff < -0x8000) {
      diff += 0xffff;
    }
    step = (int)((f32)((TrickyState *)state)->unk81A * ((TrickyState *)state)->unk4C);
    if ((diff < 0 ? -diff : diff) >= 4) {
      if ((step > 0 && diff > 0) || (step < 0 && diff < 0)) {
        if ((step < 0 ? -step : step) > (diff < 0 ? -diff : diff)) {
          *(s16 *)obj = *(s16 *)obj + diff;
        } else {
          *(s16 *)obj = *(s16 *)obj + step;
        }
      } else {
        *(s16 *)obj = *(s16 *)obj + step;
      }
    } else {
      *(s16 *)obj = *(s16 *)obj + diff;
    }
  }
  if ((((TrickyState *)state)->unk54 & 0x40) != 0) {
    ((GameObject *)obj)->anim.localPosX += ((TrickyState *)state)->unk44 * (((TrickyState *)state)->unk2C * -((TrickyState *)state)->unk814);
    ((GameObject *)obj)->anim.localPosZ += ((TrickyState *)state)->unk44 * (((TrickyState *)state)->unk30 * -((TrickyState *)state)->unk814);
  }
  if ((((TrickyState *)state)->unk54 & 0x80) != 0) {
    ((GameObject *)obj)->anim.localPosY += ((TrickyState *)state)->unk810 * ((TrickyState *)state)->unk48;
  }
  if ((((TrickyState *)state)->unk54 & 0x20) != 0) {
    ((GameObject *)obj)->anim.localPosX += ((TrickyState *)state)->unk40 * (((TrickyState *)state)->unk30 * ((TrickyState *)state)->unk80C);
    ((GameObject *)obj)->anim.localPosZ += ((TrickyState *)state)->unk40 * (((TrickyState *)state)->unk2C * -((TrickyState *)state)->unk80C);
  }
  if (*(void **)&((TrickyState *)state)->unk24 != NULL) {
    ((TrickyState *)state)->unk378 = 1;
    ((TrickyState *)state)->unk37C = *(f32 *)(*(int *)&((TrickyState *)state)->unk24 + 0x18);
    ((TrickyState *)state)->unk380 = *(f32 *)(*(int *)&((TrickyState *)state)->unk24 + 0x1c);
    ((TrickyState *)state)->unk384 = *(f32 *)(*(int *)&((TrickyState *)state)->unk24 + 0x20);
  } else {
    ((TrickyState *)state)->unk378 = 0;
  }
  if (((GameObject *)obj)->anim.currentMove == 0x2a) {
    fn_8003A168(obj,(void *)(state + 0x378));
    fn_8003B228(obj,(void *)(state + 0x378));
  } else {
    fn_8003A230(obj,(void *)(state + 0x378),lbl_803E23DC);
    characterDoEyeAnims(obj,(void *)(state + 0x378));
  }
  objAnimFn_80038f38(obj,state + 0x3a8);
  st = *(int *)&((GameObject *)obj)->extra;
  stState = (TrickyState *)st;
  p = (int)stState->unk28;
  stState->previousPathPoint = (f32 *)p;
  if (stState->previousPathPoint != NULL) {
    stState->previousPathX = *(f32 *)p;
    stState->previousPathY = *(f32 *)(p + 4);
    stState->previousPathZ = *(f32 *)(p + 8);
  }
  ((TrickyState *)state)->unk10 = ((TrickyState *)state)->unk14;
  i = ((TrickyState *)state)->unk798 - 1;
  p = state + i * 8;
  for (; i >= 0; i--) {
    *(u8 *)(p + 0x74e) = *(u8 *)(p + 0x74e) - 1;
    if (*(s8 *)(p + 0x74e) == 0) {
      memmove((void *)(p + 0x748),(void *)(state + (i + 1) * 8 + 0x748),(((TrickyState *)state)->unk798 - i - 1) * 8);
      ((TrickyState *)state)->unk798 = ((TrickyState *)state)->unk798 - 1;
    }
    p = p - 8;
  }
  if (getXZDistance(&((GameObject *)obj)->anim.worldPosX,(f32 *)(((TrickyState *)state)->playerObj + 0x18)) >= lbl_803E2538 &&
      GameBit_Get(0x4e4) != 0) {
    ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 | 0x10000;
  }
  ((TrickyState *)state)->unk79C -= timeDelta;
  if (((TrickyState *)state)->unk79C < lbl_803E23DC) {
    ((TrickyState *)state)->unk79C = lbl_803E23DC;
  }
  if ((((TrickyState *)state)->unk54 & 4) != 0) {
    st = *(int *)&((GameObject *)obj)->extra;
    if (((TrickyByteFlags *)(st + 0x58))->bit6 != 0) {
      played = 0;
    } else if (((GameObject *)obj)->anim.currentMove < 0x30 && ((GameObject *)obj)->anim.currentMove >= 0x29) {
      played = 0;
    } else if (Sfx_IsPlayingFromObjectChannel(obj,0x10) != 0) {
      played = 0;
    } else {
      objAudioFn_800393f8(obj,(void *)(st + 0x3a8),0x298,0x500,0xffffffff,0);
      played = 1;
    }
    if (played != 0) {
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0xfffffffb;
    }
  }
  ((TrickyState *)state)->unk7A0f -= timeDelta;
  if (((TrickyState *)state)->unk7A0f < lbl_803E23DC) {
    ((TrickyState *)state)->unk7A0f = lbl_803E23DC;
  }
  if (((TrickyState *)state)->unk7A0f > lbl_803E23DC) {
    TRICKY_VOICE(obj, st, 0x29c, 0x100);
  }
  trickyUpdateCollisionAndPathState((u8 *)obj);
  if ((((TrickyState *)state)->unk54 & 0x80000000) != 0) {
    ((TrickyState *)state)->unk808 -= timeDelta;
    if (((TrickyState *)state)->unk808 <= lbl_803E23DC) {
      ((TrickyState *)state)->unk54 = ((TrickyState *)state)->unk54 & 0x7fffffff;
      sfxId = ((u16 *)&pair)[randomGetRange(0,1)];
      TRICKY_VOICE(obj, st, sfxId, 0x500);
    }
  }
  fn_80138D7C(obj,state);
  Tricky_updateBlendChannelWeight(obj,state);
  if (((TrickyState *)state)->unk14 > lbl_803E254C) {
    objAudioFn_8006ef38(obj,state + 0x80c,1,state + 0x7d8,state + 0xf8,((TrickyState *)state)->unk14,lbl_803E23E8);
  }
  if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
    talking = 0;
  } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
    talking = 1;
  } else if (((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0 > lbl_803E2414) {
    talking = 1;
  } else {
    talking = 0;
  }
  if (talking != 0) {
    p = state + 0x80c;
    sfx2 = 0;
    count = *(s8 *)(p + 0x1b);
    for (i = 0; i < count; i++) {
      if (*(s8 *)(p + i + 0x13) < 3 && *(s8 *)(p + i + 0x13) >= 0) {
        sfx2 = 0x433;
      }
    }
    if (sfx2 != 0) {
      Sfx_PlayFromObject(obj,(u16)sfx2);
    }
  }
  ((TrickyState *)state)->unk8C = ((GameObject *)obj)->anim.previousLocalPosX;
  ((TrickyState *)state)->unk90 = ((GameObject *)obj)->anim.previousLocalPosY;
  ((TrickyState *)state)->unk94 = ((GameObject *)obj)->anim.previousLocalPosZ;
  if (*(int *)&((TrickyState *)state)->unk7B8 != 0) {
    ((TrickyState *)state)->unk7C0 += timeDelta;
    ((TrickyState *)state)->unk7C4 += timeDelta;
    ((TrickyState *)state)->unk7C8 += timeDelta;
    if (((TrickyState *)state)->unk7C8 > lbl_803E24C8) {
      ((TrickyState *)state)->unk7C8 -= lbl_803E24C8;
    }
    if (((TrickyState *)state)->unk7C8 >= lbl_803E2408) {
      *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) = *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) | 0x4000;
    } else {
      *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) = *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) & ~0x4000;
    }
    if (((TrickyState *)state)->unk7C4 > lbl_803E24D8) {
      if (((TrickyState *)state)->unk7C4 > lbl_803E2440) {
        ((TrickyState *)state)->unk7C4 -= lbl_803E2440;
      }
      *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) = *(s16 *)(*(int *)&((TrickyState *)state)->unk7B8 + 6) | 0x4000;
    }
    if (((TrickyState *)state)->unk7C0 > lbl_803E2550) {
      if (GameBit_Get(0xc1) != 0) {
        TRICKY_VOICE(obj, st, 0x392, 0x500);
      } else {
        TRICKY_VOICE(obj, st, 0x298, 0x500);
      }
      ((TrickyState *)state)->unk7C0 -= lbl_803E2550;
    }
    ObjAnim_AdvanceCurrentMove(lbl_803E23EC,timeDelta,*(int *)&((TrickyState *)state)->unk7B8,0);
  }
  if (*(int *)&((TrickyState *)state)->unk7B0 != 0) {
    ObjAnim_AdvanceCurrentMove(lbl_803E23EC,timeDelta,*(int *)&((TrickyState *)state)->unk7B0,0);
  }
  if (*(int *)&((TrickyState *)state)->unk7A8 != 0) {
    ObjAnim_AdvanceCurrentMove(lbl_803E23EC,timeDelta,*(int *)&((TrickyState *)state)->unk7A8,0);
  }
}

/* Tricky_init: 536b - initialize Tricky state, command callback, and path controller. */
void Tricky_init(int obj)
{
  int state;
  int model;
  int pathState;
  u32 modelVariant;
  u16 startPath[4];

  state = *(int *)&((GameObject *)obj)->extra;
  startPath[0] = lbl_803E23C0;
  GameBit_Set(0x4e3,0xff);
  if (GameBit_Get(0x25) != 0) {
    GameBit_Set(0x3f8,1);
  }
  ((GameObject *)obj)->animEventCallback = (void *)tricky_SeqFn;
  ObjGroup_AddObject(obj,1);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[0]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[1]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[2]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[3]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[4]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[5]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[6]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[7]);
  trickyVoxAllocFn_8004b5d4((void *)((TrickyState *)state)->voxBlocks[8]);
  ((TrickyState *)state)->progressPtr = (int)(*gMapEventInterface)->getProgressPtr();
  ((TrickyState *)state)->playerObj = Obj_GetPlayerObject();
  ((TrickyState *)state)->unk08 = 0;
  ((TrickyState *)state)->unk0B = 0;
  ((TrickyState *)state)->previousPathPoint = NULL;
  ((TrickyState *)state)->unkD0 = 0;
  ((TrickyState *)state)->homePosX = ((GameObject *)obj)->anim.worldPosX;
  ((TrickyState *)state)->homePosY = ((GameObject *)obj)->anim.worldPosY;
  ((TrickyState *)state)->homePosZ = ((GameObject *)obj)->anim.worldPosZ;
  modelVariant = *(u8 *)(((TrickyState *)state)->progressPtr + 2) / 10;
  modelVariant = (u8)modelVariant;
  ((TrickyState *)state)->modelVariant = modelVariant;
  model = Obj_GetActiveModel(obj);
  *(u8 *)(*(int *)(model + 0x34) + 8) = ((TrickyState *)state)->modelVariant;
  pathState = (int)&((TrickyState *)state)->pathControlFlags;
  (*gPathControlInterface)->init((void *)pathState, 1, 0xa7, 1);
  (*gPathControlInterface)->setLocalPointCollision((void *)pathState, 1, lbl_8031D300,
                                                   &lbl_803DBC48, 2);
  (*gPathControlInterface)->setup((void *)pathState, 2, lbl_8031D2E8, &lbl_803DBC40, startPath);
  (*gPathControlInterface)->attachObject((void *)obj, (void *)pathState);
  doNothing_onTrickyInit();
  walkgroupFindExitPointFn_800dc398();
  ((TrickyState *)state)->unk374 = 2;
  ((TrickyInitFlags *)&((TrickyState *)state)->unk82E)->initBit7 = 1;
  ((TrickyState *)state)->unkD = -1;
}

/* Tricky_resumeAfterCommand: resume Tricky visibility, collision, and fade after command finish. */
void Tricky_resumeAfterCommand(int obj,int state)
{
  u8 moveId;

  ((TrickyState *)state)->unk2EF = 1;
  if (((((TrickyState *)state)->flags2DC & 0x1000) != 0) &&
      ((((TrickyState *)state)->unk2E0 & 0x1000) == 0)) {
    ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
    moveId = ((TrickyState *)state)->unk320;
    ((TrickyState *)state)->unk308 = lbl_803E256C / (lbl_803E2570 * ((TrickyState *)state)->unk314);
    ((TrickyState *)state)->unk323 = 1;
    ObjAnim_SetCurrentMove(obj,moveId,lbl_803E2574,0x10);
    if (((GameObject *)obj)->anim.hitReactState != NULL) {
      ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    }
    ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 | 4;
    Sfx_PlayFromObjectLimited(obj,1099,2);
    ObjHits_EnableObject(obj);
  }
  if ((((TrickyState *)state)->flags2DC & 0x40000000) != 0) {
    ((TrickyState *)state)->unk308 = lbl_803E2578;
    ((TrickyState *)state)->unk323 = 0;
    ObjAnim_SetCurrentMove(obj,0,lbl_803E2574,0);
    if (((GameObject *)obj)->anim.hitReactState != NULL) {
      ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    }
    ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC & 0xffffef7f;
    ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 & 0xfffffffb;
    ((TrickyState *)state)->unk30C = lbl_803E2574;
    ((GameObject *)obj)->anim.alpha = 0xff;
  }
  else {
    ((GameObject *)obj)->anim.alpha = (int)(lbl_803E257C * ((GameObject *)obj)->anim.currentMoveProgress);
    ((TrickyState *)state)->unk30C = ((GameObject *)obj)->anim.currentMoveProgress;
  }
}

/* trickyFn_80148d8c: 828b - handle Tricky's completed-command fade and reward spawning. */
void trickyFn_80148d8c(int obj,int state)
{
  int setup;
  int alpha;
  void *tricky;
  u32 spawnBits;
  u8 moveId;

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  ((TrickyState *)state)->unk2EF = 0;
  if (((((TrickyState *)state)->flags2DC & 0x800) != 0) &&
      ((((TrickyState *)state)->unk2E0 & 0x800) == 0)) {
    tricky = (void *)getTrickyObject();
    if (tricky != NULL) {
      trickyImpress((int)tricky);
    }
    if ((((TrickyState *)state)->unk2E4 & 0x40000000) == 0) {
      if (*(s16 *)(setup + 0x18) != -1) {
        gameBitIncrement(*(s16 *)(setup + 0x18));
      }
      if (*(s16 *)(setup + 0x1a) != -1) {
        GameBit_Set(*(s16 *)(setup + 0x1a),0);
      }
    }
    ((TrickyState *)state)->unk29C = 0;
    ObjHits_DisableObject(obj);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
    moveId = ((TrickyState *)state)->unk321;
    ((TrickyState *)state)->unk308 = lbl_803E256C / (lbl_803E2570 * ((TrickyState *)state)->unk318);
    ((TrickyState *)state)->unk323 = 1;
    ObjAnim_SetCurrentMove(obj,moveId,lbl_803E2574,0);
    if (*(int *)&((GameObject *)obj)->anim.hitReactState != 0) {
      ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    }
    ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 | 1;
    Sfx_PlayFromObject(obj,SFXdoor_creak);
    if (randomGetRange(0,100) > 50) {
      if ((((TrickyState *)state)->unk2E4 & 0x100000) != 0) {
        collectibleFn_80149cec(obj,state,((TrickyState *)state)->unk2F5,0,4);
      }
      else {
        spawnBits = *(s16 *)(setup + 0x22) & 0xf00;
        if (spawnBits != 0) {
          collectibleFn_80149cec(obj,state,spawnBits,0,1);
        }
        spawnBits = *(s16 *)(setup + 0x22) & 0xf000;
        if (spawnBits != 0) {
          collectibleFn_80149cec(obj,state,spawnBits,0,2);
        }
        spawnBits = *(s16 *)(setup + 0x22) & 0xff;
        if (spawnBits != 0) {
          collectibleFn_80149cec(obj,state,spawnBits,0,3);
        }
      }
    }
  }
  alpha = 0xff - (int)(lbl_803E257C * ((GameObject *)obj)->anim.currentMoveProgress);
  if (alpha < 0) {
    alpha = 0;
  }
  else if (alpha > 0xff) {
    alpha = 0xff;
  }
  ((GameObject *)obj)->anim.alpha = alpha;
  ((TrickyState *)state)->unk30C =
      lbl_803E256C + (f32)(0xff - ((GameObject *)obj)->anim.alpha) / lbl_803E257C;
  if (((GameObject *)obj)->anim.alpha < 5) {
    if ((((TrickyState *)state)->unk2E4 & 0x40000000) != 0) {
      if (*(s16 *)(setup + 0x18) != -1) {
        gameBitIncrement(*(s16 *)(setup + 0x18));
      }
      if (*(s16 *)(setup + 0x1a) != -1) {
        GameBit_Set(*(s16 *)(setup + 0x1a),0);
      }
    }
    ((TrickyState *)state)->unk30C = lbl_803E2574;
    ((TrickyState *)state)->flags2DC = 0;
    ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    ((GameObject *)obj)->anim.alpha = 0;
    *(u32 *)&((GameObject *)obj)->unkF4 = 1;
    if (((ObjPlacement *)setup)->mapId == -1) {
      Obj_FreeObject(obj);
    }
    else {
      if (*(s16 *)(setup + 0x2c) != 0) {
        (*gMapEventInterface)->startTimedEvent(((ObjPlacement *)setup)->mapId,
                                               lbl_803E2570 * (f32)*(s16 *)(setup + 0x2c));
      }
      ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC & 0xfffff7ff;
      ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 & ~3;
    }
  }
}

/* collectibleFn_80149cec: 876b - spawn or reposition Tricky reward objects from packed command bits. */
int collectibleFn_80149cec(int obj,int state,int spawnBits,u32 useAltMode,u32 mode)
{
  u32 commandSpawnIds[2];
  struct TrickyRewardSpawnTail {
    u32 pair;
    u16 single;
  } rewardTail;
  f32 nearestDistance;
  u32 rewardSpawnIds0;
  int parentSetup;
  int setup;
  int index;
  f32 savedX;
  f32 savedY;
  f32 savedZ;
  f32 v;

  (void)state;
  parentSetup = *(int *)&((GameObject *)obj)->anim.placementData;
  commandSpawnIds[0] = lbl_803E2558;
  commandSpawnIds[1] = lbl_803E255C;
  rewardSpawnIds0 = lbl_803E2560;
  rewardTail.pair = lbl_803E2564;
  rewardTail.single = lbl_803E2568;
  if (spawnBits == 0) {
    return 0;
  }
  if (Obj_IsLoadingLocked() == 0) {
    return 0;
  }
  mode = (u8)mode;
  if (mode == 1) {
    index = ((spawnBits & 0xf00) >> 8) - 1;
    if (index > 3) {
      index = 3;
    }
    setup = Obj_AllocObjectSetup(0x30,*(u16 *)((int)commandSpawnIds + index * 2));
  }
  else if (mode == 2) {
    index = ((spawnBits & 0xf000) >> 0xc) - 1;
    if (index > 1) {
      index = 1;
    }
    setup = Obj_AllocObjectSetup(0x30,*(u16 *)((int)&rewardSpawnIds0 + index * 2));
  }
  else if (mode == 3) {
    switch (spawnBits) {
    case 3:
      setup = Obj_AllocObjectSetup(0x30,0xb);
      break;
    case 1:
    case 4:
      setup = Obj_AllocObjectSetup(0x30,0x2cd);
      break;
    case 5:
      savedX = ((GameObject *)obj)->anim.worldPosX;
      savedY = ((GameObject *)obj)->anim.worldPosY;
      savedZ = ((GameObject *)obj)->anim.worldPosZ;
      parentSetup = *(int *)&((GameObject *)obj)->anim.placementData;
      if ((void *)parentSetup != NULL) {
        ((GameObject *)obj)->anim.worldPosX = *(f32 *)(parentSetup + 8);
        ((GameObject *)obj)->anim.worldPosY = *(f32 *)(parentSetup + 0xc);
        ((GameObject *)obj)->anim.worldPosZ = *(f32 *)(parentSetup + 0x10);
      }
      nearestDistance = lbl_803E25A8;
      lbl_803DDA54 = ObjGroup_FindNearestObject(4,obj,&nearestDistance);
      ((GameObject *)obj)->anim.worldPosX = savedX;
      ((GameObject *)obj)->anim.worldPosY = savedY;
      ((GameObject *)obj)->anim.worldPosZ = savedZ;
      if ((void *)lbl_803DDA54 != NULL) {
        v = ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)lbl_803DDA54)->anim.worldPosX = v;
        ((GameObject *)lbl_803DDA54)->anim.localPosX = v;
        v = lbl_803E25AC + ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)lbl_803DDA54)->anim.worldPosY = v;
        ((GameObject *)lbl_803DDA54)->anim.localPosY = v;
        v = ((GameObject *)obj)->anim.localPosZ;
        ((GameObject *)lbl_803DDA54)->anim.worldPosZ = v;
        ((GameObject *)lbl_803DDA54)->anim.localPosZ = v;
      }
      return lbl_803DDA54;
    default:
      return 0;
    }
  }
  else if (mode == 4) {
    index = spawnBits;
    if (index > 3) {
      index = 3;
    }
    if (index <= 0) {
      return 0;
    }
    setup = Obj_AllocObjectSetup(0x30,((u16 *)&rewardTail.pair)[index - 1]);
  }
  *(u8 *)(setup + 0x1a) = 0x14;
  *(s16 *)(setup + 0x2c) = -1;
  *(s16 *)(setup + 0x1c) = -1;
  *(s16 *)(setup + 0x24) = -1;
  ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
  ((ObjPlacement *)setup)->posY = lbl_803E2598 + ((GameObject *)obj)->anim.localPosY;
  ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
  if ((useAltMode & 0xff) != 0) {
    *(s16 *)(setup + 0x2e) = 2;
  }
  else {
    *(s16 *)(setup + 0x2e) = 1;
  }
  *(u8 *)(setup + 4) = *(u8 *)(parentSetup + 4);
  *(u8 *)(setup + 6) = *(u8 *)(parentSetup + 6);
  *(u8 *)(setup + 5) = *(u8 *)(parentSetup + 5);
  *(u8 *)(setup + 7) = *(u8 *)(parentSetup + 7);
  lbl_803DDA54 = Obj_SetupObject(setup,5,((GameObject *)obj)->anim.mapEventSlot,-1,*(int *)&((GameObject *)obj)->anim.parent);
  if ((((GameObject *)lbl_803DDA54)->anim.seqId == 0x3cd) ||
      (((GameObject *)lbl_803DDA54)->anim.seqId == 0xb)) {
    (*(void (**)(f32,f32,f32))(*(int *)(*(int *)&((GameObject *)lbl_803DDA54)->anim.dll) + 0x2c))
        (lbl_803E2574,lbl_803E256C,lbl_803E2574);
  }
  return lbl_803DDA54;
}

/* baddie_updateWhileFrozen: 2796b - shared frozen-state update + per-baddie reaction dispatch. */
typedef struct {
  s16 rot[3];
  f32 scale;
  Vec pos;
} FrozenFxParams;

typedef struct {
  int c0;
  int c1;
  int c2;
  int c3;
} FrozenFxColors;

typedef struct {
  u8 fadeCounter : 5;
  u8 low : 3;
} FrozenByte2F6;

extern f32 sqrtf(f32 x);
extern int getAngle(f32 x, f32 z);
void frozenEnemyFn_80149bb4(int *obj, u32 flags, f32 f, u16 val);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_802C2200[];
extern int *lbl_803DCAB4;
extern int *lbl_803DDA50;
extern f32 lbl_803E2588;
extern f32 lbl_803E258C;
extern f32 lbl_803E2590;
extern f32 lbl_803E2594;
extern f32 lbl_803E259C;
extern void fn_802972B4(int player, uint *outEffects, f32 *outA, f32 *outB, f32 *outC, u16 *outSfx);
extern void vecRotateZXY(int obj, void *vel);
extern int objCreateLight(int a, int b);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_StartModelFadeIn(int obj, int duration);
extern void fn_802961FC(u8 *proj, int result);
extern int fn_801504F8(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector, f32 hDist, f32 vDist);
extern void fn_80152004(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80152440(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80152B2C(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80152FA8(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80153790(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80153CF8(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_801544E8(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void rachnopUpdateWhileFrozen(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void wbUpdateWhileFrozen(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void baddieUpdateWhileFrozen_80155e10(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void mutatedEbaUpdateWhileFrozen(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void smallbasket_nop(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void smallbasket_handleReactionEvent(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void hoodedZyckUpdateWhileFrozen(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_8014FEF8(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void fn_80157EBC(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);
extern void smallbasket_handleHitStateEvent(int obj, u8 *state, int attacker, int hit, int p5, int p6, Vec *hitPos, int sector);

void baddie_updateWhileFrozen(int obj, u8 *state, u8 fromHit)
{
  int player;
  int hit;
  int result;
  u16 sector;
  int diff;
  f32 hDist;
  f32 vDist;
  u8 *proj;
  f32 *dp;
  f32 zero;
  FrozenFxParams params;
  Vec hitPos;
  f32 delta[3];
  FrozenFxColors colors;
  int attacker;
  f32 fxA;
  f32 fxB;
  f32 fxC;
  int hitArg;
  int hitCount;
  uint hitEffects;
  u16 impactSfx;

  player = Obj_GetPlayerObject();
  colors = *(FrozenFxColors *)lbl_802C2200;
  result = 2;
  if ((((TrickyState *)state)->flags2DC & 0x1800) == 0) {
    if ((((TrickyState *)state)->unk2E4 & 1) != 0) {
      ObjHits_EnableObject(obj);
    } else {
      ObjHits_DisableObject(obj);
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj,&attacker,&hitArg,&hitCount,&hitPos.x,&hitPos.y,&hitPos.z);
    hitPos.x += playerMapOffsetX;
    hitPos.z += playerMapOffsetZ;
    ((TrickyState *)state)->unk2D4 -= timeDelta;
    if (hit == 0x1a) {
      if (((TrickyState *)state)->unk2D4 >= lbl_803E2574) {
        hit = 0;
      } else {
        ((TrickyState *)state)->unk2D4 = lbl_803E2588;
      }
    }
    ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC & 0xffffffcf;
    ((TrickyState *)state)->unk2D8 -= timeDelta;
    if (((TrickyState *)state)->unk2D8 < lbl_803E2574) {
      ((TrickyState *)state)->unk2D8 = lbl_803E2574;
    }
    fn_802972B4(player,&hitEffects,&fxA,&fxB,&fxC,&impactSfx);
    frozenEnemyFn_80149bb4((int *)state,hitEffects,fxA,impactSfx);
    if (hit != 0) {
      if (fromHit) {
        if (hit != 0x10) {
          params.scale = lbl_803E258C;
          ((void (**)(int,int,int,int,void *))*(int *)lbl_803DCAB4)[3](obj,0x7fb,0,0x64,&params);
          ((void (**)(int,int,int,int,void *))*(int *)lbl_803DCAB4)[3](obj,0x7fc,0,0x32,0);
          Obj_ResetModelColorState(obj);
          *(u16 *)&((TrickyState *)state)->unk2B0 = 0;
          ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 & 0xffffffdf;
          ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 | 0x200;
          Sfx_PlayFromObject(obj,0x47b);
        } else {
          ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 | 0x10;
        }
      } else {
        if (hitEffects != 0) {
          if (*(s16 *)(attacker + 0x44) == 1 || *(s16 *)(attacker + 0x44) == 0x2d) {
            if ((((TrickyState *)state)->unk2E4 & 0x200) != 0) {
              if (fxC >= lbl_803E2590 && fxC <= lbl_803E256C) {
                ((TrickyState *)state)->unk304 = fxC;
              }
              zero = lbl_803E2574;
              ((GameObject *)obj)->anim.velocityX = zero;
              ((GameObject *)obj)->anim.velocityY = zero;
              if ((((TrickyState *)state)->flags2DC & 0x40) != 0) {
                ((GameObject *)obj)->anim.velocityZ = lbl_803E2594 * fxB;
              } else {
                ((GameObject *)obj)->anim.velocityZ = fxB;
              }
              vecRotateZXY(obj,(void *)(obj + 0x24));
            }
          }
        }
        ((TrickyState *)state)->unk2D8 += lbl_803E2598 * (f32)hitCount;
        if ((((TrickyState *)state)->flags2DC & 0x4000) != 0) {
          ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC | 0x10;
        }
        if ((((TrickyState *)state)->flags2DC & 0x40) == 0) {
          ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC | 0x4000;
        }
        ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC | 0x20;
        dp = delta;
        dp[0] = ((GameObject *)obj)->anim.worldPosX - hitPos.x;
        dp[1] = ((GameObject *)obj)->anim.worldPosY - hitPos.y;
        dp[2] = ((GameObject *)obj)->anim.worldPosZ - hitPos.z;
        diff = (u16)getAngle(-dp[0],-dp[2]) - (u16)*(s16 *)obj;
        if (diff > 0x8000) {
          diff -= 0xffff;
        }
        if (diff < -0x8000) {
          diff += 0xffff;
        }
        sector = (uint)(u16)diff >> 13;
        hDist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
        vDist = sqrtf(dp[1] * dp[1]);
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x11: case 0x13a: case 0x5b7: case 0x5b8: case 0x5b9: case 0x5e1: case 0x7a6:
          result = fn_801504F8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector,hDist,vDist);
          break;
        case 0xd8: case 0x281:
          fn_80152004(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x613:
          fn_80152440(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x642:
          fn_80152B2C(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x3fe: case 0x7c6:
          fn_80152FA8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x58b:
          fn_80153790(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x369:
          fn_80153CF8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x251:
          fn_801544E8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x25d:
          rachnopUpdateWhileFrozen(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x4d7:
          wbUpdateWhileFrozen(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x457:
          baddieUpdateWhileFrozen_80155e10(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x458:
          mutatedEbaUpdateWhileFrozen(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x851:
          smallbasket_nop(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x842: case 0x84b:
          smallbasket_handleReactionEvent(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x4ac:
          hoodedZyckUpdateWhileFrozen(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x427:
          fn_8014FEF8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x6a2: case 0x6a3: case 0x6a4: case 0x6a5:
          fn_80157EBC(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        case 0x7c8:
          smallbasket_handleHitStateEvent(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        default:
          fn_8014FEF8(obj,state,attacker,hit,hitArg,hitCount,&hitPos,sector);
          break;
        }
      }
    } else {
      if ((((TrickyState *)state)->flags2DC & 0x40000000) != 0) {
        ((TrickyState *)state)->flags2DC = ((TrickyState *)state)->flags2DC & 0xffffbfff;
      }
    }
    if ((((TrickyState *)state)->unk2E8 & 0x208) != 0) {
      params.pos.x = hitPos.x;
      params.pos.y = hitPos.y;
      params.pos.z = hitPos.z;
      if (*(void **)&((TrickyState *)state)->unk368 == NULL) {
        ((TrickyState *)state)->unk368 = objCreateLight(0,1);
      }
      if ((((TrickyState *)state)->unk2E8 & 0x200) != 0) {
        objLightFn_8009a1dc((void *)obj,lbl_803E259C,&params,1,(void *)((TrickyState *)state)->unk368);
      } else if ((((TrickyState *)state)->unk2F1 & 0x10) != 0) {
        objLightFn_8009a1dc((void *)obj,lbl_803E259C,&params,3,(void *)((TrickyState *)state)->unk368);
      } else if ((((TrickyState *)state)->unk2F1 & 8) != 0) {
        objLightFn_8009a1dc((void *)obj,lbl_803E259C,&params,2,(void *)((TrickyState *)state)->unk368);
      } else {
        objLightFn_8009a1dc((void *)obj,lbl_803E259C,&params,1,(void *)((TrickyState *)state)->unk368);
      }
      Obj_SetModelColorFadeRecursive(obj,0xf,0xc8,0,0,1);
    }
    ((TrickyState *)state)->unk2D0 -= timeDelta;
    if (((TrickyState *)state)->unk2D0 < lbl_803E2574) {
      ((TrickyState *)state)->unk2D0 = lbl_803E2574;
    }
    if ((((TrickyState *)state)->unk2E8 & 0x10) != 0) {
      if (((TrickyState *)state)->unk2D0 <= lbl_803E2574) {
        params.pos.x = hitPos.x;
        params.pos.y = hitPos.y;
        params.pos.z = hitPos.z;
        params.scale = lbl_803E256C;
        params.rot[2] = 0;
        params.rot[1] = 0;
        params.rot[0] = 0;
        if (lbl_803DDA50 != NULL) {
          ((void (**)(int,int,void *,int,int,void *))*(int *)lbl_803DDA50)[1](0,1,&params,0x401,-1,&colors);
        }
        ((TrickyState *)state)->unk2D0 = lbl_803E25A0;
        if (*(void **)&((TrickyState *)state)->unk368 == NULL) {
          ((TrickyState *)state)->unk368 = objCreateLight(0,1);
        }
        objLightFn_8009a1dc((void *)obj,lbl_803E259C,&params,4,(void *)((TrickyState *)state)->unk368);
      }
      proj = *(u8 **)&((TrickyState *)state)->unk29C;
      if (proj != NULL && *(s16 *)(proj + 0x44) == 1) {
        fn_802961FC(proj,result);
      }
    } else if ((((TrickyState *)state)->unk2E8 & 0x20) != 0) {
      if (((FrozenByte2F6 *)((TrickyState *)state)->pad2F6)->fadeCounter == 0) {
        Sfx_PlayFromObject(obj,0x47a);
        ((FrozenByte2F6 *)((TrickyState *)state)->pad2F6)->fadeCounter = 0x1f;
      }
      Obj_StartModelFadeIn(obj,0x12c);
    } else {
      if (((FrozenByte2F6 *)((TrickyState *)state)->pad2F6)->fadeCounter != 0) {
        ((FrozenByte2F6 *)((TrickyState *)state)->pad2F6)->fadeCounter -= 1;
      }
    }
    ((TrickyState *)state)->unk2E8 = ((TrickyState *)state)->unk2E8 & 0xfffffdc7;
  }
}

/* baddieInstantiateWeapon: 248b - refresh Tricky's attached child object when its setup id changes. */
void baddieInstantiateWeapon(int obj,int state)
{
  int parentSetup;
  void *child;
  int setup;

  parentSetup = *(int *)&((GameObject *)obj)->anim.placementData;
  if ((*(s16 *)&((TrickyState *)state)->unk2B4 != *(s16 *)(state + 0x2b6)) &&
      (((GameObject *)obj)->anim.alpha != 0)) {
    if (((GameObject *)obj)->unkC8 != NULL) {
      child = ((GameObject *)obj)->unkC8;
      ObjLink_DetachChild(obj, (int)child);
      Obj_FreeObject((int)child);
    }
    if (Obj_IsLoadingLocked() != 0) {
      if (*(s16 *)(state + 0x2b6) > 0) {
        setup = Obj_AllocObjectSetup(0x20);
        *(u8 *)(setup + 5) = *(u8 *)(setup + 5) | (*(u8 *)(parentSetup + 5) & 0x18);
        child = (void *)Obj_SetupObject(setup,4,((GameObject *)obj)->anim.mapEventSlot,-1,*(int *)&((GameObject *)obj)->anim.parent);
        ObjLink_AttachChild(obj, (int)child, 0);
        *(s16 *)&((TrickyState *)state)->unk2B4 = *(s16 *)(state + 0x2b6);
      }
    }
    else {
      *(s16 *)&((TrickyState *)state)->unk2B4 = 0;
    }
  }
}

/* baddieTargetFn_8014a150: 436b - line-of-sight and bbox visibility check between Tricky and a target. */
u8 baddieTargetFn_8014a150(int obj,int state,void *from,void *to)
{
  u8 traceHit[4];
  s16 toGrid[4];
  s16 fromGrid[4];
  Vec probe;
  Vec delta;
  u8 bboxHit[TRICKY_BBOX_HIT_SCRATCH_SIZE];
  s16 setupId;
  u8 visible;
  int keepGroundOffset;

  traceHit[0] = 0;
  visible = 0;
  if (((TrickyState *)state)->unk29C != 0) {
    probe.x = *(f32 *)((int)from + 0);
    probe.y = *(f32 *)((int)from + 4);
    probe.z = *(f32 *)((int)from + 8);
    keepGroundOffset = 1;
    setupId = ((GameObject *)obj)->anim.seqId;
    if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
        ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
        ((setupId != 0x251) && (setupId != 0x851))) {
      probe.y += lbl_803E25A0;
      keepGroundOffset = 0;
    }
    voxmaps_worldToGrid(&probe,fromGrid);
    probe.x = *(f32 *)((int)to + 0);
    probe.y = lbl_803E25A0 + *(f32 *)((int)to + 4);
    probe.z = *(f32 *)((int)to + 8);
    voxmaps_worldToGrid(&probe,toGrid);
    PSVECSubtract((Vec *)from,&probe,&delta);
    if (PSVECMag(&delta) < lbl_803E25B0) {
      if (*(u32 *)&((GameObject *)obj)->anim.parent == 0) {
        visible = voxmaps_traceLine(toGrid,fromGrid,0,traceHit,0);
      }
      if ((keepGroundOffset == 0) && (traceHit[0] == 1)) {
        visible = 1;
      }
    }
  }
  if ((visible != 0) && ((((TrickyState *)state)->unk2E4 & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) != 0)) {
    if (objBboxFn_800640cc((Vec *)from,&probe,lbl_803E256C,0,bboxHit,obj,((TrickyState *)state)->unk261,
                           -1,0,0) != 0) {
      visible = 0;
    }
  }
  return visible;
}

/* baddieFn_8014a304: 760b - update Tricky's four quadrant line-of-sight state bits. */
void baddieFn_8014a304(f32 radius,int obj,int state)
{
  u8 traceHit[4];
  s16 probeGrid[4];
  s16 baseGrid[4];
  Vec probe;
  u32 visibilityBits[4];
  Vec delta;
  u8 bboxHit[TRICKY_BBOX_HIT_SCRATCH_SIZE];
  s16 baseAngle;
  int i;
  u8 visible;
  f32 angle;
  f32 angleScale;
  f32 angleDivisor;
  f32 maxDistance;
  s16 setupId;

  *(longlong *)&visibilityBits[0] = *(longlong *)&lbl_802C21F0[0];
  *(longlong *)&visibilityBits[2] = *(longlong *)&lbl_802C21F0[2];
  probe.x = ((GameObject *)obj)->anim.localPosX;
  probe.y = lbl_803E25A0 + ((GameObject *)obj)->anim.localPosY;
  probe.z = ((GameObject *)obj)->anim.localPosZ;
  voxmaps_worldToGrid(&probe,baseGrid);
  if (*(u32 *)&((GameObject *)obj)->anim.parent != 0) {
    baseAngle = *(s16 *)obj + **(s16 **)&((GameObject *)obj)->anim.parent;
  }
  else {
    baseAngle = *(s16 *)obj;
  }
  angleScale = lbl_803E25B4;
  angleDivisor = lbl_803E25B8;
  maxDistance = lbl_803E25B0;
  for (i = 0; i < 4; i++) {
    angle = (angleScale * (f32)((s32)baseAngle + ((u32)(u16)i << 0xe))) / angleDivisor;
    probe.x = ((GameObject *)obj)->anim.worldPosX - (radius * mathSinf(angle));
    probe.y = ((GameObject *)obj)->anim.worldPosY;
    probe.z = ((GameObject *)obj)->anim.worldPosZ - (radius * mathCosf(angle));
    setupId = ((GameObject *)obj)->anim.seqId;
    if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
        ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
        ((setupId != 0x251) && (setupId != 0x851))) {
      probe.y += lbl_803E25A0;
    }
    voxmaps_worldToGrid(&probe,probeGrid);
    PSVECSubtract((Vec *)(obj + 0x18),&probe,&delta);
    if (PSVECMag(&delta) < maxDistance) {
      if (*(u32 *)&((GameObject *)obj)->anim.parent != 0) {
        visible = 1;
      }
      else {
        visible = voxmaps_traceLine(probeGrid,baseGrid,0,traceHit,0);
        if (traceHit[0] == 1) {
          visible = 1;
        }
      }
    }
    else {
      visible = 0;
    }
    if ((visible != 0) && ((((TrickyState *)state)->unk2E4 & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) != 0)) {
      if (objBboxFn_800640cc((Vec *)(obj + 0x18),&probe,lbl_803E256C,0,bboxHit,obj,
                             ((TrickyState *)state)->unk261,-1,0,0) != 0) {
        visible = 0;
      }
    }
    if (visible != 0) {
      ((TrickyState *)state)->flags2DC |= visibilityBits[i];
    }
    else {
      ((TrickyState *)state)->flags2DC &= ~visibilityBits[i];
    }
  }
}

void Tricky_findNearbyFloorHeights(int obj,int state,f32 *nearestFloorY,f32 *nearestSpecialY);

/* Tricky_applyFloorResponse: apply Tricky floor response and movement-control callbacks. */
void Tricky_applyFloorResponse(int obj,int state)
{
  f32 nearestFloorY;
  f32 nearestSpecialY;
  f32 points[6];
  u32 flags;
  f32 dy;

  ((TrickyState *)state)->flags2DC &= 0xf7efffff;
  flags = ((TrickyState *)state)->unk2E4;
  if ((flags & TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK) != 0) {
    Tricky_findNearbyFloorHeights(obj,state,&nearestFloorY,&nearestSpecialY);
    flags = ((TrickyState *)state)->unk2E4;
    if ((flags & TRICKY_CONTROL_FLAG_USE_SPECIAL_FLOOR_Y) != 0) {
      ((GameObject *)obj)->anim.velocityY = (nearestSpecialY - ((GameObject *)obj)->anim.localPosY) * oneOverTimeDelta;
    }
    else if ((flags & TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y) != 0) {
      dy = nearestFloorY - ((GameObject *)obj)->anim.localPosY;
      if ((lbl_803E25BC < dy) && (dy < lbl_803E25A0)) {
        ((GameObject *)obj)->anim.velocityY = (lbl_803E25C0 + dy) * oneOverTimeDelta;
        ((TrickyState *)state)->flags2DC |= TRICKY_STATE_FLAG_SPECIAL_FLOOR_RESPONSE;
      }
    }
    else {
      dy = nearestFloorY - ((GameObject *)obj)->anim.localPosY;
      if ((lbl_803E25BC < dy) && (dy < lbl_803E25A0)) {
        ((GameObject *)obj)->anim.velocityY = dy * oneOverTimeDelta;
        ((TrickyState *)state)->flags2DC |= TRICKY_STATE_FLAG_FLOOR_RESPONSE;
      }
    }
    if ((((TrickyState *)state)->unk2E4 & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) == 0) {
      ((TrickyState *)state)->unk25F = 0;
    }
  }
  else {
    if ((flags & 0xc) != 0) {
      ((TrickyState *)state)->unk25F = 1;
    }
    else {
      ((TrickyState *)state)->unk25F = 0;
    }
  }

  (*gPathControlInterface)->update((void *)obj, (void *)(state + 4), timeDelta);
  if ((((TrickyState *)state)->unk2E4 & 4) != 0) {
    (*gPathControlInterface)->apply((void *)obj, (void *)(state + 4));
  }
  (*gPathControlInterface)->advance((void *)obj, (void *)(state + 4), timeDelta);

  if (((*(s8 *)&((TrickyState *)state)->unk25F != 0) &&
       ((((TrickyState *)state)->unk2E4 & TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK) == 0)) &&
      ((((TrickyState *)state)->unk264 & TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR) != 0)) {
    ((GameObject *)obj)->anim.velocityY = lbl_803E2574;
    ((TrickyState *)state)->flags2DC |= TRICKY_STATE_FLAG_FLOOR_RESPONSE;
  }
  if ((((TrickyState *)state)->unk2E4 & 0x00200000) != 0) {
    ObjPath_GetPointWorldPositionArray(obj,2,2,points);
    objAudioFn_8006edcc(((TrickyState *)state)->unk310,lbl_803E256C,obj,((TrickyState *)state)->unk2F8,7,points,
                (void *)(state + 4));
  }
}

/* Tricky_findNearbyFloorHeights: find nearby floor heights and special surface deltas for Tricky. */
void Tricky_findNearbyFloorHeights(int obj,int state,f32 *nearestFloorY,f32 *nearestSpecialY)
{
  int hitList[2];
  u16 hitCount;
  u16 i;
  f32 *hit;
  f32 hitY;
  f32 dy;
  f32 absDy;
  f32 defaultY;
  f32 nearestFloorDelta;
  f32 nearestSpecialDelta;

  defaultY = lbl_803E25C4;
  *nearestFloorY = defaultY;
  *nearestSpecialY = defaultY;
  hitCount = hitDetectFn_80065e50(((GameObject *)obj)->anim.localPosX,((GameObject *)obj)->anim.localPosY,
                                  ((GameObject *)obj)->anim.localPosZ,obj,hitList,0,0);
  *nearestFloorY = ((GameObject *)obj)->anim.localPosY;
  *nearestSpecialY = ((GameObject *)obj)->anim.localPosY;
  nearestFloorDelta = lbl_803E25C8;
  nearestSpecialDelta = nearestFloorDelta;
  ((TrickyState *)state)->flags2DC &= ~TRICKY_STATE_FLAG_SPECIAL_FLOOR_ABOVE;
  ((TrickyState *)state)->unk1B8 = lbl_803E2574;
  *(s8 *)&((TrickyState *)state)->unk264 &= ~TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
  for (i = 0; i < hitCount; i++) {
    hit = *(f32 **)(hitList[0] + ((u32)i << 2));
    hitY = hit[0];
    dy = hitY - ((GameObject *)obj)->anim.localPosY;
    absDy = dy;
    if (dy < lbl_803E2574) {
      absDy = -dy;
    }
    if (*(s8 *)(hit + 5) == 0xe) {
      if (absDy < nearestSpecialDelta) {
        ((TrickyState *)state)->unk1B8 = dy;
        *(s8 *)&((TrickyState *)state)->unk264 |= TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
        *nearestSpecialY = **(f32 **)(hitList[0] + ((u32)i << 2));
        nearestSpecialDelta = absDy;
        if (lbl_803E25A0 < ((TrickyState *)state)->unk1B8) {
          ((TrickyState *)state)->flags2DC |=
              TRICKY_STATE_FLAG_SPECIAL_FLOOR_ABOVE | TRICKY_STATE_FLAG_FLOOR_RESPONSE;
        }
      }
    }
    else if (absDy < nearestFloorDelta) {
      *nearestFloorY = hitY;
      *(s8 *)&((TrickyState *)state)->unk264 |= TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
      nearestFloorDelta = absDy;
    }
  }
}

/*
 * --INFO--
 *
 * Function: Tricky_render
 * EN v1.0 Address: 0x801463BC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Tricky_render(int obj,int param_2,int param_3,int param_4,int param_5,char doRender)
{
  u8 mode;
  int state;
  int pathState;
  int pathPoint;
  int i;
  int pathInfo;

  if (doRender != '\0') {
    state = *(int *)&((GameObject *)obj)->extra;
    objRenderFn_8003b8f4(obj,param_2,param_3,param_4,param_5,lbl_803E23E8);
    pathState = *(int *)&((GameObject *)obj)->extra;
    i = 0;
    pathPoint = pathState;
    do {
      ObjPath_GetPointWorldPosition(obj,i + 4,(float *)(pathPoint + 0x3d8),
                   (undefined4 *)(pathPoint + 0x3dc),(float *)(pathPoint + 0x3e0),0);
      pathPoint = pathPoint + 0xc;
      i = i + 1;
    } while (i < 4);
    ObjPath_GetPointWorldPosition(obj,8,(float *)(pathState + 0x408),
                 (undefined4 *)(pathState + 0x40c),(float *)(pathState + 0x410),0);
    pathInfo = objModelGetVecFn_800395d8(obj,0);
    *(s16 *)(pathState + 0x414) = *(s16 *)(pathInfo + 2);
    if ((((TrickyState *)state)->unk54 & 0x10) != 0) {
      switch (((TrickyState *)state)->unk08) {
      case 2:
        fn_8013ADFC(obj);
        break;
      case 3:
        if (((TrickyState *)state)->unkA == 4) {
          fn_8013ADFC(obj);
        }
        break;
      }
      if ((((((TrickyState *)state)->unk54 & 0x200) == 0) && (((TrickyState *)state)->unk08 == 0xb)) &&
         (((TrickyState *)state)->unkA >= 3)) {
        if (((TrickyState *)state)->unkA != 3) {
          *(f32 *)(*(int *)&((TrickyState *)state)->unk700 + 0xc) = ((TrickyState *)state)->unk408;
          *(f32 *)(*(int *)&((TrickyState *)state)->unk700 + 0x10) = ((TrickyState *)state)->unk40C;
          *(f32 *)(*(int *)&((TrickyState *)state)->unk700 + 0x14) = ((TrickyState *)state)->unk410;
        }
        objRenderFn_8003b8f4(*(int *)&((TrickyState *)state)->unk700,param_2,param_3,param_4,param_5,lbl_803E23E8);
      }
    }
    Tricky_emitQueuedPathParticles(obj,state);
    ObjPath_GetPointWorldPositionArray(obj,4,4,(float *)((TrickyState *)state)->pad7D8);
    ((TrickyState *)state)->unk838 = ((TrickyState *)state)->unk838 - timeDelta;
    if (((TrickyState *)state)->unk838 > lbl_803E23DC) {
      objParticleFn_80099d84(obj,lbl_803E253C,6,lbl_803E23E8,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: Tricky_hitDetect
 * EN v1.0 Address: 0x8014658C
 * EN v1.0 Size: 500b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Tricky_hitDetect(int obj)
{
  f32 y;
  f32 dy;
  int *objects;
  int i;
  void *firepipeObj;
  int state;
  f32 height;
  int count[2];

  state = *(int *)&((GameObject *)obj)->extra;
  y = ((GameObject *)obj)->anim.localPosY;
  dy = y - ((GameObject *)obj)->anim.previousLocalPosY;
  if (dy < lbl_803E23DC) {
    dy = -dy;
  }
  if (lbl_803E23E8 == dy) {
    if (y == ((GameObject *)obj)->anim.worldPosY) {
      ((TrickyStatusFlags58 *)&((TrickyState *)state)->unk58)->heightTracking = 1;
      *(s32 *)&((TrickyState *)state)->unk5C = -1;
      ((TrickyState *)state)->unk60 = lbl_803E23DC;
    }
  }
  else {
    firepipeObj = ObjList_FindObjectById(TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID);
    if ((firepipeObj != (void *)0) &&
        (getXZDistance(&((GameObject *)obj)->anim.worldPosX,(f32 *)((int)firepipeObj + 0x18)) < lbl_803E2540)) {
      ((TrickyStatusFlags58 *)&((TrickyState *)state)->unk58)->heightTracking = 1;
      ((TrickyState *)state)->unk5C = TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID;
      ((TrickyState *)state)->unk60 = lbl_803E23DC;
    }
  }
  if ((((TrickyState *)state)->unk58 >> 5 & 1) != 0) {
    objects = ObjGroup_GetObjects(TRICKY_HEIGHT_TRACK_GROUP,count);
    for (i = 0; i < count[0]; i++) {
      height = objFn_801948c0(*objects,TRICKY_HEIGHT_TRACK_MODEL_SLOT);
      if (*(s32 *)&((TrickyState *)state)->unk5C == -1) {
        dy = height - ((GameObject *)obj)->anim.localPosY;
        if (dy < lbl_803E23DC) {
          dy = -dy;
        }
        if (dy < lbl_803E24B8) {
          ((TrickyState *)state)->unk5C = *(u32 *)(*(int *)(*objects + 0x4c) + 0x14);
        }
      }
      if (((TrickyState *)state)->unk5C == *(u32 *)(*(int *)(*objects + 0x4c) + 0x14)) {
        if ((((TrickyState *)state)->unk60 == lbl_803E23DC) ||
           (((TrickyState *)state)->unk60 != height)) {
          ((GameObject *)obj)->anim.localPosY = height;
          ((TrickyState *)state)->unk60 = height;
        }
        else {
          ((TrickyStatusFlags58 *)&((TrickyState *)state)->unk58)->heightTracking = 0;
        }
        break;
      }
      objects = objects + 1;
    }
    if (i == count[0]) {
      ((TrickyStatusFlags58 *)&((TrickyState *)state)->unk58)->heightTracking = 0;
    }
  }
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_80146fa0
 * EN v1.0 Address: 0x80146FA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148FF0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146fa0(void)
{
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_80147884
 * EN v1.0 Address: 0x80147884
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x8014A5B0
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147884(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,float *param_12)
{
  short sVar1;
  bool bVar2;
  int *piVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  char local_a0 [4];
  short asStack_9c [4];
  short asStack_94 [4];
  float afStack_8c [3];
  float local_80;
  float local_7c;
  float local_78;
  int aiStack_74 [29];
  
  uVar7 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  local_a0[0] = '\0';
  cVar4 = '\0';
  if (*(int *)(iVar5 + 0x29c) != 0) {
    local_80 = *param_11;
    local_7c = param_11[1];
    local_78 = param_11[2];
    bVar2 = true;
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_7c = local_7c + lbl_803E3234;
      bVar2 = false;
    }
    FUN_80006a68(&local_80,asStack_9c);
    local_80 = *param_12;
    local_7c = lbl_803E3234 + param_12[1];
    local_78 = param_12[2];
    FUN_80006a68(&local_80,asStack_94);
    FUN_80247eb8(param_11,&local_80,afStack_8c);
    dVar6 = SeekTwiceBeforeRead(afStack_8c);
    if (dVar6 < (double)lbl_803E3244) {
      if (piVar3[0xc] == 0) {
        cVar4 = FUN_80006a64(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_94,asStack_9c,(undefined4 *)0x0,local_a0,0);
      }
      if ((!bVar2) && (local_a0[0] == '\x01')) {
        cVar4 = '\x01';
      }
    }
  }
  if ((cVar4 != '\0') && ((*(uint *)(iVar5 + 0x2e4) & 8) != 0)) {
    FUN_800620e8(param_11,&local_80,(float *)0x0,aiStack_74,piVar3,(uint)*(byte *)(iVar5 + 0x261),
                 0xffffffff,0,0);
  }
  FUN_80286888();
  return;
}


/* 8b "li r3, N; blr" returners. */
int Tricky_getExtraSize(void) { return 0x83c; }

/* misc 16b 4-insn patterns. */
u8 Tricky_func0E(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x1); }
u8 Tricky_render2(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x0); }

/* Tricky_getCurrentCommandType: 24b - write state command byte 0xd to the outparam. */
int Tricky_getCurrentCommandType(int *obj, int *out) {
    *out = *((s8*)obj[0xb8/4] + 0xd);
    return 1;
}

extern u8 Objfsa_GetWalkGroupIndexAtPoint(void *pos,int param_2);
extern int Objfsa_GetPatchGroupIdAtPoint(void *pos);
extern void walkPath_writeU16LE(int pathId,u8 *out);
extern int Objfsa_FindNearestEnabledCurveType24(void *pos,int param_2,int param_3);

/* trickyFn_801451d8: 300b - seed Tricky's path state and ensure the helper object exists. */
int trickyFn_801451d8(int obj,int state) {
    u8 pathBytes[16];
    u32 pathByte = Objfsa_GetWalkGroupIndexAtPoint((void *)(obj + 0x18), 0);

    pathByte = (u8)pathByte;
    pathBytes[0] = pathByte;
    if (pathByte == 0) {
        int pathId = Objfsa_GetPatchGroupIdAtPoint((void *)(obj + 0x18));
        if (pathId != 0) {
            walkPath_writeU16LE(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0) {
        f32 resetTimer;

        ((TrickyState *)state)->unk532 = pathBytes[0];
        ((TrickyState *)state)->unk08 = 1;
        ((TrickyState *)state)->unkA = 0;
        resetTimer = lbl_803E23DC;
        ((TrickyState *)state)->unk71C = resetTimer;
        ((TrickyState *)state)->unk720 = resetTimer;
        *(s32 *)&((TrickyState *)state)->unk54 = *(s32 *)&((TrickyState *)state)->unk54 & -17;
        *(s32 *)&((TrickyState *)state)->unk54 = *(s32 *)&((TrickyState *)state)->unk54 & -65537;
        *(s32 *)&((TrickyState *)state)->unk54 = *(s32 *)&((TrickyState *)state)->unk54 & -131073;
        *(s32 *)&((TrickyState *)state)->unk54 = *(s32 *)&((TrickyState *)state)->unk54 & -262145;
        ((TrickyState *)state)->unkD = -1;
    }
    if (lbl_803DDA48 == 0) {
        int setup = Obj_AllocObjectSetup(0x18, 0x25);
        lbl_803DDA48 = Obj_SetupObject(setup, 4, -1, -1, *(int *)&((GameObject *)obj)->anim.parent);
    }
    {
        int ret = 1;
        ((TrickyByteFlags *)&((TrickyState *)state)->unk58)->bit7 = ret;
        return ret;
    }
}

/* Tricky_func11: 72b - if GameBit_Get(0x4e4), OR 0x10000 into obj->_b8->_54. */
void Tricky_func11(int *obj) {
    register int *p = (int*)obj[0xb8/4];
    if (GameBit_Get(0x4e4)) {
        p[0x54/4] |= 0x10000;
    }
}

/* Tricky_func13: 40b - lbz/cmplwi(8/0xe) selector returning 1 or 0. */
int Tricky_func13(int *obj) {
    u8 v = *((u8*)obj[0xb8/4] + 8);
    if (v == 8 || v == 0xe) return 1;
    return 0;
}

/* Tricky_func12: 36b - cmpwi(5) selector returning 1 or 0. */
int Tricky_func12(int *obj) {
    u8 v;
    int r;
    v = *((u8*)obj[0xb8/4] + 8);
    switch (v) {
    case 5:
        r = 1;
        break;
    default:
        r = 0;
        break;
    }
    return r;
}

/* Tricky_func10: enter state 10 against targetObj, or queue it while Tricky is busy. */
int Tricky_func10(int *obj,int targetObj) {
    int *state = (int*)obj[0xb8/4];
    s32 objBlocked = ((GameObject *)obj)->objectFlags & 0x1000;

    if (objBlocked != 0) {
        return 0;
    }
    if (((u32)state[0x54/4] & 0x10) == 0) {
        state[0x24/4] = targetObj;
        if ((void*)state[0x28/4] != (void*)(targetObj + 0x18)) {
            state[0x28/4] = targetObj + 0x18;
            state[0x54/4] = state[0x54/4] & ~0x400;
            *(s16*)((u8*)state + 0xd2) = 0;
        }
        *((u8*)state + 10) = 0;
        *((u8*)state + 8) = 10;
    } else {
        u32 queuedTargetMask = 0x10000;

        *((u8*)state + 0x7d0) = 1;
        state[0x7d4/4] = targetObj;
        state[0x54/4] = state[0x54/4] | queuedTargetMask;
    }
    return 1;
}

/* Tricky_func0F: start or refresh state 5 against a nearby curve target. */
void Tricky_func0F(int *obj,int commandEnabled,int targetObj) {
    register int *state = (int*)obj[0xb8/4];

    if (commandEnabled != 0) {
        if (*((u8*)state + 8) == 5) {
            if (*((u8*)state + 10) != 0) {
                state[0x24/4] = targetObj;
            }
        } else {
            u32 busy = state[0x54/4] & 0x10;
            void *nextTarget;
            if (busy != 0) {
                return;
            }
            state[0x700/4] = Objfsa_FindNearestEnabledCurveType24((void *)(targetObj + 0x18), -1, 3);
            *(f32*)((u8*)state + 0x710) = (f32)(int)randomGetRange(0x168, 0x28);
            *((u8*)state + 8) = 5;
            state[0x24/4] = targetObj;
            nextTarget = (void *)(state[0x700/4] + 8);
            if ((void *)state[0x28/4] != nextTarget) {
                state[0x28/4] = (int)nextTarget;
                state[0x54/4] &= ~0x400;
                *(s16*)((u8*)state + 0xd2) = 0;
            }
            *((u8*)state + 10) = 0;
        }
    } else {
        state[0x54/4] |= 0x10000;
    }
}

/* Tricky_getAvailableCommands: 124b - GameBit_Get cascade returning command flags. */
int Tricky_getAvailableCommands(void) {
    int r = 0;
    if (GameBit_Get(0x4e4) != 0) {
        r = 0xa;
        if (GameBit_Get(0xdd) != 0) r |= 0x1;
        if (GameBit_Get(0x25) != 0) r |= 0x20;
        if (GameBit_Get(0x245) != 0) r |= 0x10;
    }
    return r;
}

/* trickyReportError: 80b - varargs OSReport-style stub. */
void trickyReportError(const char *fmt, ...) { }

/* trickyDebugPrint: 80b - varargs OSReport-style stub. */
void trickyDebugPrint(const char *fmt, ...) { }

extern f32 lbl_803E25A4;
extern f32 lbl_803E2500;
extern f32 lbl_803E2418;

/* Tricky_findNearestGroup4BObject: find nearest object within distance threshold. */
u8 *Tricky_findNearestGroup4BObject(u8 *obj, TrickyState *state) {
    int *objs;
    int count[1];
    u8 *result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = ObjGroup_GetObjects(0x4b, count);
    d = getXZDistance((f32*)((char*)state->playerObj + 0x18), &((GameObject *)obj)->anim.worldPosX);
    if ((d >= lbl_803E2538) || (state->unk71C > lbl_803E23DC)) {
        if (ViewFrustum_IsSphereVisible(&((GameObject *)obj)->anim.localPosX, lbl_803E2500) == 0) {
            bestD = lbl_803E2418;
            for (i = 0; i < count[0]; i++) {
                f32 cd = getXZDistance((f32*)((char*)state->playerObj + 0x18), (f32*)((char*)*objs + 0x18));
                if (cd < d && cd < bestD) {
                    bestD = cd;
                    result = (u8 *)*objs;
                }
                objs++;
            }
        }
    }
    return result;
}

/* trickyFn_80144f50: 648b - update Tricky's water/out-of-water probe and animation. */
void trickyFn_80144f50(int obj, int state) {
    int sfxState;
    int isInWater;
    u32 sfxDisabled;
    u32 transitionFlag;

    if (trickyFoodFn_8014460c(obj, state) == 0) {
        ((TrickyState *)state)->unk72C =
            ((GameObject *)obj)->anim.worldPosX - mathSinf((lbl_803E2454 * (f32)*(s16*)obj) / lbl_803E2458);
        *(f32 *)&((TrickyState *)state)->unk730 = ((GameObject *)obj)->anim.worldPosY;
        ((TrickyState *)state)->unk734 =
            ((GameObject *)obj)->anim.worldPosZ - mathCosf((lbl_803E2454 * (f32)*(s16*)obj) / lbl_803E2458);

        if (trickyFn_8013b368(obj, lbl_803E247C, state) != 1) {
            ((TrickyState *)state)->unk740 -= timeDelta;
            if (((TrickyState *)state)->unk740 <= lbl_803E23DC) {
                ((TrickyState *)state)->unk740 = (f32)(int)randomGetRange(0x1f4, 0x2ee);
                sfxState = *(int *)&((GameObject *)obj)->extra;
                sfxDisabled = (*(u8*)(sfxState + 0x58) >> 6) & 1;
                if ((sfxDisabled == 0) &&
                    ((((GameObject *)obj)->anim.currentMove >= 0x30) || (((GameObject *)obj)->anim.currentMove < 0x29)) &&
                    (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)) {
                    objAudioFn_800393f8(obj, (void*)(sfxState + 0x3a8), 0x360, 0x500, -1, 0);
                }
            }

            if (lbl_803E23DC == ((TrickyState *)state)->unk2AC) {
                isInWater = 0;
            } else if (lbl_803E2410 == ((TrickyState *)state)->unk2B0) {
                isInWater = 1;
            } else if ((((TrickyState *)state)->unk2B4 - ((TrickyState *)state)->unk2B0) > lbl_803E2414) {
                isInWater = 1;
            } else {
                isInWater = 0;
            }

            if (isInWater) {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState *)state)->unk79C = lbl_803E2440;
                ((TrickyState *)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch (((GameObject *)obj)->anim.currentMove) {
                case 0x31:
                    break;
                case 0xd:
                    transitionFlag = ((TrickyState *)state)->unk54 & 0x08000000;
                    if (transitionFlag != 0) {
                        objAnimFn_8013a3f0(obj, 0x31, lbl_803E243C, 0);
                    }
                    break;
                default:
                    objAnimFn_8013a3f0(obj, 0xd, lbl_803E2444, 0);
                    break;
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}


/* frozenEnemyFn_80149bb4: 312b - flag bits to byte field. */
void frozenEnemyFn_80149bb4(int *obj, u32 flags, f32 f, u16 val) {
    *((u8*)obj + 0x2f1) = 0;
    if ((flags & 0x2) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x20);
    }
    if ((flags & 0x1) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x40);
    }
    if ((flags & 0x4) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x1);
    }
    if ((flags & 0x8) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x2);
    }
    if ((flags & 0x10) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x4);
    }
    if (lbl_803E25A4 == f) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x8);
    } else if (lbl_803E2594 == f) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x10);
    }
    if ((flags & 0x80) != 0) {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x80);
    }
    if ((flags & 0x100) != 0) {
        *((u8*)obj + 0x2f5) = 1;
    } else if ((flags & 0x200) != 0) {
        *((u8*)obj + 0x2f5) = 2;
    } else if ((flags & 0x400) != 0) {
        *((u8*)obj + 0x2f5) = 3;
    }
    *(u16*)((char*)obj + 0x2ec) = val;
}
