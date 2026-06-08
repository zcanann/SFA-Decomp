#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

/* SB_Propeller_getExtraSize == 0x10. */
typedef struct SBPropellerState {
    f32 smokeTimer; /* 0x00: countdown to the next smoke burst */
    f32 spinBlend;  /* 0x04 */
    int spinRate;   /* 0x08: init 1200 */
    s8 health;      /* 0x0c: init 4 */
    u8 pad0D[3];
} SBPropellerState;
STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

/* SB_ShipHead_getExtraSize == 0x10. */
typedef struct SBShipHeadState {
    int target;     /* 0x00: the 0x8c galleon-side object */
    s8 health;      /* 0x04: init 4 */
    u8 pad05[3];
    f32 swayA;      /* 0x08 */
    f32 swayB;      /* 0x0c */
} SBShipHeadState;
STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);
#include "main/objhits_types.h"

#pragma peephole off
#pragma scheduling off
extern undefined4 getLActions();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_8001792c();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a54();
extern undefined8 FUN_80017a7c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_8005d0ac();
extern undefined4 FUN_80080f5c();
extern undefined4 FUN_80080f60();
extern undefined4 FUN_80080f64();
extern undefined4 FUN_80080f68();
extern undefined4 FUN_80080f74();
extern undefined4 FUN_80080f78();
extern double FUN_80081014();
extern undefined4 FUN_8008112c();
extern undefined4 SH_LevelControl_runBloopEvent();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_802c2b78;
extern undefined4 DAT_802c2b7c;
extern undefined4 DAT_802c2b80;
extern undefined4 DAT_802c2b84;
extern undefined4 DAT_802c2b88;
extern undefined4 DAT_802c2b8c;
extern undefined4 DAT_802c2b90;
extern undefined4 DAT_802c2b94;
extern undefined4 DAT_802c2b98;
extern undefined4 DAT_802c2b9c;
extern undefined4 DAT_802c2ba0;
extern undefined4 DAT_802c2ba4;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcce0;
extern undefined4 DAT_803dcce4;
extern undefined4 DAT_803dcce8;
extern undefined4 DAT_803dccec;
extern undefined4 DAT_803dccf0;
extern undefined4 DAT_803dccf4;
extern undefined4 DAT_803dccf8;
extern undefined4* DAT_803dd6e4;
extern EffectInterface **gPartfxInterface;
extern undefined4 DAT_803de898;
extern undefined4 DAT_803de89c;
extern undefined4 DAT_803de8a0;
extern undefined4 DAT_803de8ac;
extern undefined4 DAT_803de8ad;
extern undefined4 DAT_803de8b0;
extern undefined4 DAT_803de8b4;
extern undefined4 DAT_803de8b8;
extern undefined4 DAT_803de8c0;
extern undefined4 DAT_803de8c8;
extern f64 DOUBLE_803e6458;
extern f64 DOUBLE_803e6480;
extern f64 DOUBLE_803e64c0;
extern f64 DOUBLE_803e64f8;
extern f32 lbl_803DC074;
extern f32 lbl_803DE8A4;
extern f32 lbl_803DE8A8;
extern f32 lbl_803E6360;
extern f32 lbl_803E6364;
extern f32 lbl_803E6388;
extern f32 lbl_803E63BC;
extern f32 lbl_803E63D0;
extern f32 lbl_803E6428;
extern f32 lbl_803E643C;
extern f32 lbl_803E644C;
extern f32 lbl_803E6460;
extern f32 lbl_803E6464;
extern f32 lbl_803E6468;
extern f32 lbl_803E646C;
extern f32 lbl_803E6470;
extern f32 lbl_803E6474;
extern f32 lbl_803E6478;
extern f32 lbl_803E6488;
extern f32 lbl_803E648C;
extern f32 lbl_803E6490;
extern f32 lbl_803E6494;
extern f32 lbl_803E6498;
extern f32 lbl_803E649C;
extern f32 lbl_803E64A0;
extern f32 lbl_803E64A4;
extern f32 lbl_803E64A8;
extern f32 lbl_803E64AC;
extern f32 lbl_803E64B0;
extern f32 lbl_803E64B4;
extern f32 lbl_803E64B8;
extern f32 lbl_803E64BC;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;
extern f32 lbl_803E64D8;
extern f32 lbl_803E64DC;
extern f32 lbl_803E64E0;
extern f32 lbl_803E64E4;
extern f32 lbl_803E64E8;
extern f32 lbl_803E64EC;
extern f32 lbl_803E64F0;
extern f32 lbl_803E64F4;
extern undefined bRam803dcce1;
extern undefined2 bRam803dcce2;
extern undefined bRam803dcce5;
extern undefined2 bRam803dcce6;
extern undefined bRam803dcce9;
extern undefined2 bRam803dccea;
extern undefined bRam803dcced;
extern undefined2 bRam803dccee;
extern undefined bRam803dccf1;
extern undefined2 bRam803dccf2;
extern undefined bRam803dccf5;
extern undefined2 bRam803dccf6;
extern undefined bRam803de8b9;
extern undefined2 bRam803de8ba;
extern undefined uRam803de8b1;
extern undefined2 uRam803de8b2;
extern undefined uRam803de8b5;
extern undefined2 uRam803de8b6;

/*
 * --INFO--
 *
 * Function: SB_Galleon_animEventCallback
 * EN v1.0 Address: 0x801E1AAC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x801E18DC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void DBprotection_storeHomePosition(int obj);
extern int ObjList_GetObjects(int *start, int *end);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Music_Trigger(s32 snd, s32 mode);
extern f32 lbl_803E56CC;
extern void Sfx_StopFromObject(int obj, int sfxId);
extern u32 fn_801E2570(void);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern f32 lbl_803E57F4;
extern f32 lbl_803E57F8;
extern f32 lbl_803E5790;
extern f32 timeDelta;
int SB_Galleon_animEventCallback(int obj, int p2, int msgSrc) {
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;
    *(s8 *)(obj + 0xac) = -1;
    fn_801E1588(obj, state);
    {
        f32 z = lbl_803E56CC;
        ((SBGalleonState *)state)->moveScale = lbl_803E56CC;
        ((SBGalleonState *)state)->swayX = z;
        ((SBGalleonState *)state)->swayY = z;
        ((SBGalleonState *)state)->swayZ = z;
    }
    *(void **)(msgSrc + 0xe8) = (void *)DBprotection_storeHomePosition;
    for (i = 0; i < *(u8 *)(msgSrc + 0x8b); i++) {
        switch (*(u8 *)(msgSrc + i + 0x81)) {
        case 2:
            if (((SBGalleonState *)state)->unk79 == 1) {
                ((SBGalleonState *)state)->unk79 = 0;
            }
            else {
                ((SBGalleonState *)state)->unk79 = 1;
            }
            break;
        case 3: {
            int start;
            int end;
            int *arr = (int *)ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++) {
                if (*(s16 *)(arr[i] + 0x46) == 0xf7) {
                    ((SBGalleonState *)state)->linkedActor = arr[i];
                    i = end;
                }
            }
            ((SBGalleonState *)state)->sprayActive = 1;
            break;
        }
        case 4:
            ((SBGalleonState *)state)->sprayActive = 0;
            break;
        case 5:
            if (((SBGalleonState *)state)->unk79 == 2) {
                ((SBGalleonState *)state)->unk79 = 0;
            }
            else {
                ((SBGalleonState *)state)->unk79 = 2;
            }
            break;
        case 6:
            Sfx_PlayFromObject(obj, 0x143);
            break;
        case 7:
            Sfx_StopFromObject(obj, 0x143);
            break;
        case 8:
            if (((SBGalleonState *)state)->unk79 == 8) {
                ((SBGalleonState *)state)->unk79 = 1;
            }
            else {
                ((SBGalleonState *)state)->unk79 = 8;
            }
            break;
        case 9:
            ((SBGalleonState *)state)->skyFlag = 1;
            break;
        case 10:
            ((SBGalleonState *)state)->skyFlag = 0;
            break;
        case 0xb:
            Sfx_PlayFromObject(fn_801E2570(), 0x2c6);
            break;
        case 0xc:
            ((SBGalleonState *)state)->musicIdB = 0xa3;
            Music_Trigger(((SBGalleonState *)state)->musicIdB, 1);
            Music_Trigger(((SBGalleonState *)state)->musicIdA, 0);
            break;
        case 0xd:
            ((SBGalleonState *)state)->textTimer = lbl_803E57F8;
            ((SBGalleonState *)state)->textRising = 1;
            ((SBGalleonState *)state)->textAlpha = lbl_803E56CC;
            break;
        }
    }
    {
        f32 z = lbl_803E56CC;
        if (((SBGalleonState *)state)->textTimer >= z) {
            ((SBGalleonState *)state)->textTimer = ((SBGalleonState *)state)->textTimer - timeDelta;
            if (((SBGalleonState *)state)->textTimer < z) {
                ((SBGalleonState *)state)->textTimer = z;
                ((SBGalleonState *)state)->textRising = 0;
            }
        }
    }
    if (((SBGalleonState *)state)->textRising != 0) {
        ((SBGalleonState *)state)->textAlpha = lbl_803E5790 * timeDelta + ((SBGalleonState *)state)->textAlpha;
    }
    else {
        ((SBGalleonState *)state)->textAlpha = -(lbl_803E5790 * timeDelta - ((SBGalleonState *)state)->textAlpha);
    }
    {
        f32 v = ((SBGalleonState *)state)->textAlpha;
        f32 c = lbl_803E56CC;
        if (!(v < lbl_803E56CC)) {
            c = lbl_803E57F4;
            if (!(v > lbl_803E57F4)) {
                c = v;
            }
        }
        ((SBGalleonState *)state)->textAlpha = c;
    }
    if (((SBGalleonState *)state)->textAlpha > lbl_803E56CC) {
        gameTextSetColor(0xff, 0xff, 0xff, (int)((SBGalleonState *)state)->textAlpha);
        gameTextShow(0x4b1);
    }
    ((SBGalleonState *)state)->posX = ((GameObject *)obj)->anim.localPosX;
    ((SBGalleonState *)state)->posY = ((GameObject *)obj)->anim.localPosY;
    ((SBGalleonState *)state)->posZ = ((GameObject *)obj)->anim.localPosZ;
    *(s16 *)(msgSrc + 0x6e) = *(s16 *)(msgSrc + 0x70);
    *(u8 *)(msgSrc + 0x56) = 0;
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 1316b
 * EN v1.1 Address: 0x801E1B78
 * EN v1.1 Size: 1316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    f32 x, y, z;
} SkyVec3;

extern void setDrawLights(int mode);
extern void skySetOverrideLightColorEnabled(int on);
extern void skySetOverrideLightColor(int r, int g, int b);
extern void skyFn_80089710(int a, int b, int c);
extern f32 fn_8008ED88(void);
extern void skyFn_800895e0(int idx, int r, int g, int b, int a, int b2);
extern void fn_80089510(int idx, int r, int g, int b);
extern void fn_80089578(int idx, int r, int g, int b);
extern void skySetOverrideLightDirectionEnabled(int on);
extern void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 w);
extern void skyFn_800894a8(int idx, f32 x, f32 y, f32 z);
extern int *Obj_GetActiveModel(int obj);
extern int ObjModel_GetRenderOp(int model, int idx);
extern f32 lbl_802C23F8[12];
extern u8 lbl_803DC078[4];
extern u8 lbl_803DC07C[4];
extern u8 lbl_803DC080[4];
extern u8 lbl_803DC084[4];
extern u8 lbl_803DC088[4];
extern u8 lbl_803DC08C[4];
extern f32 lbl_803DDC24;
extern f32 lbl_803DDC28;
extern u8 lbl_803DDC2D;
extern u8 lbl_803DDC30[3];
extern u8 lbl_803DDC34[3];
extern u8 lbl_803DDC38[3];
extern f32 lbl_803E57A4;
extern f32 lbl_803E57B4;
extern f32 lbl_803E57E0;
extern f32 lbl_803E57F0;
extern f32 lbl_803E5724;
void fn_801E1588(int obj, int state)
{
  int *model;
  int i;
  int rop;
  SkyVec3 a;
  SkyVec3 b;
  SkyVec3 c;
  SkyVec3 d;
  a = ((SkyVec3 *)lbl_802C23F8)[0];
  b = ((SkyVec3 *)lbl_802C23F8)[1];
  c = ((SkyVec3 *)lbl_802C23F8)[2];
  d = ((SkyVec3 *)lbl_802C23F8)[3];
  setDrawLights(0);
  skySetOverrideLightColorEnabled(1);
  skySetOverrideLightColor(0x29, 0x4b, 0xa9);
  skyFn_80089710(7, 1, 0);
  if (fn_8008ED88() > lbl_803E56CC) {
    lbl_803DDC24 = lbl_803E57A4;
    lbl_803DDC28 = lbl_803E57A4;
  }
  lbl_803DDC28 = -(lbl_803E57B4 * timeDelta - lbl_803DDC28);
  if (lbl_803DDC28 < lbl_803E56CC) {
    lbl_803DDC28 = lbl_803E56CC;
  }
  {
    int v0 = lbl_803DC080[0];
    lbl_803DDC38[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC084[0] - v0);
  }
  {
    int v1 = lbl_803DC080[1];
    lbl_803DDC38[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC084[1] - v1);
  }
  {
    int v2 = lbl_803DC080[2];
    lbl_803DDC38[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC084[2] - v2);
  }
  skyFn_800895e0(7, lbl_803DDC38[0], lbl_803DDC38[1], lbl_803DDC38[2], 0x40, 0x40);
  {
    int v0 = lbl_803DC078[0];
    lbl_803DDC34[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC07C[0] - v0);
  }
  {
    int v1 = lbl_803DC078[1];
    lbl_803DDC34[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC07C[1] - v1);
  }
  {
    int v2 = lbl_803DC078[2];
    lbl_803DDC34[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC07C[2] - v2);
  }
  fn_80089510(7, lbl_803DDC34[0], lbl_803DDC34[1], lbl_803DDC34[2]);
  {
    int v0 = lbl_803DC088[0];
    lbl_803DDC30[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC08C[0] - v0);
  }
  {
    int v1 = lbl_803DC088[1];
    lbl_803DDC30[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC08C[1] - v1);
  }
  {
    int v2 = lbl_803DC088[2];
    lbl_803DDC30[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC08C[2] - v2);
  }
  fn_80089578(7, lbl_803DDC30[0], lbl_803DDC30[1], lbl_803DDC30[2]);
  lbl_803DDC2D = lbl_803DDC28 * lbl_803E57E0 + lbl_803E57F0;
  skySetOverrideLightDirectionEnabled(1);
  skySetOverrideLightDirection(lbl_803DDC28 * (d.x - c.x) + c.x,
                               lbl_803DDC28 * (d.y - c.y) + c.y,
                               lbl_803DDC28 * (d.z - c.z) + c.z, lbl_803E5724);
  if (((SBGalleonState *)state)->skyFlag == 0) {
    skyFn_800894a8(7, a.x, a.y, a.z);
  }
  else {
    skyFn_800894a8(7, b.x, b.y, b.z);
  }
  model = Obj_GetActiveModel(obj);
  i = 0;
  {
    f32 scale = lbl_803E57F4;
    for (; i < *(u8 *)(*model + 0xf8); i++) {
      rop = ObjModel_GetRenderOp(*model, i);
      if (*(u8 *)(rop + 0x29) == 1) {
        *(u8 *)(rop + 0xc) = scale * lbl_803DDC28;
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801e1ee4
 * EN v1.0 Address: 0x801E1EE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E2398
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e1ee4(void)
{
  return DAT_803de8a0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e2184
 * EN v1.0 Address: 0x801E2184
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E2B60
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e2184(void)
{
  return DAT_803de8c0;
}

/*
 * --INFO--
 *
 * Function: SB_Propeller_update
 * EN v1.0 Address: 0x801E21B4
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: 0x801E2BBC
 * EN v1.1 Size: 1212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int p);
extern void spawnExplosion(f32 s, int obj, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E5810;
extern f32 lbl_803E5814;
extern f32 lbl_803E5818;
extern f32 lbl_803E581C;
extern f32 lbl_803E5820;
extern f32 lbl_803E5824;
void SB_Propeller_update(int obj) {
    ObjAnimComponent *objAnim;
    int camA;
    int camB;
    int camC;
    int i;
    int hit;
    f32 *pf;
    struct {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;

    objAnim = (ObjAnimComponent *)obj;
    pf = ((GameObject *)obj)->extra;
    camA = (**(int (**)(int))(**(int **)(*(int *)&((GameObject *)obj)->anim.parent + 0x68) + 0x24))(*(int *)&((GameObject *)obj)->anim.parent);
    camB = (**(int (**)(int))(**(int **)(*(int *)&((GameObject *)obj)->anim.parent + 0x68) + 0x28))(*(int *)&((GameObject *)obj)->anim.parent);
    if (((((SBPropellerState *)pf)->health != 0) && (camB < 6)) && (((GameObject *)obj)->anim.seqId != 0x69c)) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x2c6);
    }
    camC = DBprotection_getCameraState(*(int *)&((GameObject *)obj)->anim.parent);
    if ((camC < 2) && (((SBPropellerState *)pf)->health < 1)) {
        ((SBPropellerState *)pf)->smokeTimer = ((SBPropellerState *)pf)->smokeTimer - timeDelta;
        if (((SBPropellerState *)pf)->smokeTimer <= lbl_803E5814) {
            f32 spd = lbl_803E5810;
            for (i = randomGetRange(10, 0x19); i != 0; i--) {
                stk.b = ((GameObject *)obj)->anim.worldPosX;
                stk.c = ((GameObject *)obj)->anim.worldPosY;
                stk.d = ((GameObject *)obj)->anim.worldPosZ;
                stk.a = spd;
                (*gPartfxInterface)->spawnObject((void *)obj, 0x9f, stk.pad, 0x200001, -1, NULL);
            }
            ((SBPropellerState *)pf)->smokeTimer = (f32)(int)randomGetRange(0x5a, 0xf0);
        }
        if ((2 < camA) && (objAnim->bankIndex == 1)) {
            stk.a = lbl_803E5818;
            stk.mode = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - ((GameObject *)obj)->anim.worldPosX;
            stk.c = stk.c - ((GameObject *)obj)->anim.worldPosY;
            stk.d = stk.d - ((GameObject *)obj)->anim.worldPosZ;
            for (i = 0; i < framesThisStep; i++) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x7aa, stk.pad, 2, -1, NULL);
            }
        }
    }
    if (*(int *)&((GameObject *)obj)->anim.parent != 0) {
        if ((((GameObject *)obj)->anim.seqId != 0x69c) && (*(int *)(*(int *)&((GameObject *)obj)->anim.parent + 0xf4) < 4)) {
            ((SBPropellerState *)pf)->spinBlend = (f32)((SBPropellerState *)pf)->spinRate / lbl_803E581C;
            if (((SBPropellerState *)pf)->spinBlend < lbl_803E5814) {
                ((SBPropellerState *)pf)->spinBlend = -((SBPropellerState *)pf)->spinBlend;
            }
            if (((SBPropellerState *)pf)->spinBlend < *(f32 *)&lbl_803E5820) {
                ((SBPropellerState *)pf)->spinBlend = lbl_803E5820;
            }
        }
        ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 - framesThisStep;
        if (((GameObject *)obj)->unkF4 < 0) {
            ((GameObject *)obj)->unkF4 = 0;
        }
        if (((((((camB == 1) && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0))
               && (((GameObject *)obj)->unkF4 == 0))
              && ((hit != 0 && (hit != Obj_GetPlayerObject()))))
             && ((*(s16 *)(hit + 0x46) != 0x69c
                  && ((*(s16 *)(hit + 0x46) != 0x9a
                       && ((((GameObject *)obj)->unkF4 = 0x14, *(int *)&((GameObject *)obj)->anim.parent != 0)))))))
            && ((camA == 2 || (camA == 5)))) && (((GameObject *)obj)->anim.seqId == 0x69c)) {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, 0x2c7);
            ((SBPropellerState *)pf)->health -= 1;
            if (((SBPropellerState *)pf)->health <= 0) {
                *(u8 *)&((SBPropellerState *)pf)->health = 0;
                (**(void (**)(int))(**(int **)(*(int *)&((GameObject *)obj)->anim.parent + 0x68) + 0x20))(*(int *)&((GameObject *)obj)->anim.parent);
                ObjHits_DisableObject(obj);
                *(u16 *)&((GameObject *)obj)->anim.flags = *(u16 *)&((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
                spawnExplosion(lbl_803E5824, obj, 1, 1, 1, 0, 1, 1, 0);
                Sfx_PlayFromObject(obj, 0x2c8);
            }
        }
        if (((GameObject *)obj)->unkF4 == 0) {
            ObjHitsPriorityState *hitState = *(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState;
            hitState->hitVolumePriority = 6;
            hitState->hitVolumeId = 1;
            hitState->objectHitMask = 0x10;
            hitState->skeletonHitMask = 0x10;
        }
        else {
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairPriority = 0;
        }
        ((GameObject *)obj)->anim.rotZ = (int)-((f32)((SBPropellerState *)pf)->spinRate * timeDelta - (f32)((GameObject *)obj)->anim.rotZ);
    }
}

/*
 * --INFO--
 *
 * Function: SB_Propeller_init
 * EN v1.0 Address: 0x801E2708
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E3078
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SB_Propeller_init(int param_1,int param_2)
{
  ObjAnimComponent *objAnim;
  uint uVar1;
  float *pfVar2;
  
  objAnim = (ObjAnimComponent *)param_1;
  pfVar2 = *(float **)(param_1 + 0xb8);
  uVar1 = randomGetRange(0x5a,0xf0);
  ((SBPropellerState *)pfVar2)->smokeTimer = (f32)(s32)(uVar1);
  ((SBPropellerState *)pfVar2)->spinBlend = lbl_803E64A8;
  ((SBPropellerState *)pfVar2)->spinRate = 1200;
  *(u8 *)&((SBPropellerState *)pfVar2)->health = 4;
  objAnim->bankIndex = (char)*(s16 *)(param_2 + 0x1a);
  if (*(short *)(param_1 + 0x46) != 0x69c) {
    DAT_803de8c0 = param_1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: SB_ShipHead_render
 * EN v1.0 Address: 0x801E27C4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801E314C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SB_ShipHead_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int iVar2;
  byte bVar3;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  if (visible != 0) {
    iVar2 = *(int *)(param_1 + 0xb8);
    FUN_8003b818(param_1);
    iVar1 = *(int *)(param_1 + 0x30);
    if ((((iVar1 != 0) && (*(short *)(iVar1 + 0x46) == 0x8e)) &&
        (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x2c))(), iVar1 != 0)) && (iVar1 != 2)) {
      ((SBShipHeadState *)iVar2)->swayA = ((SBShipHeadState *)iVar2)->swayA - lbl_803DC074;
      if (((SBShipHeadState *)iVar2)->swayA <= lbl_803E64CC) {
        ((SBShipHeadState *)iVar2)->swayA = ((SBShipHeadState *)iVar2)->swayA + lbl_803E64D0;
      }
      ((SBShipHeadState *)iVar2)->swayB = ((SBShipHeadState *)iVar2)->swayB - lbl_803DC074;
      if (((SBShipHeadState *)iVar2)->swayB <= lbl_803E64CC) {
        ((SBShipHeadState *)iVar2)->swayB = ((SBShipHeadState *)iVar2)->swayB + lbl_803E64C8;
      }
      local_20 = lbl_803E64D4;
      local_22 = 0xc0a;
      ObjPath_GetPointWorldPosition(param_1,0xd,&local_1c,&local_18,local_14,0);
      local_1c = local_1c - *(float *)(param_1 + 0x18);
      local_18 = local_18 - *(float *)(param_1 + 0x1c);
      local_14[0] = local_14[0] - *(float *)(param_1 + 0x20);
      for (bVar3 = 0; bVar3 < DAT_803dc070; bVar3 = bVar3 + 1) {
        (*gPartfxInterface)->spawnObject((void *)param_1, 0x7aa, auStack_28, 2, -1, NULL);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: SB_ShipHead_update
 * EN v1.0 Address: 0x801E2940
 * EN v1.0 Size: 1892b
 * EN v1.1 Address: 0x801E32D4
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u32 getSbGalleon(void);
extern f32 Vec_distance(void *a, void *b);
extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32 *x, f32 *y, f32 *z);
extern u8 *Obj_AllocObjectSetup(int size, int objId);
extern int Obj_SetupObject(u8 *setup, int a, int b, int c, int d);
extern u8 lbl_803DC090;
extern int lbl_803DDC48;
extern f32 lbl_803E5834;
extern f32 lbl_803E5840;
extern f32 lbl_803E5844;
extern f32 lbl_803E5848;
extern f32 lbl_803E584C;
extern f32 lbl_803E5850;
extern f32 lbl_803E5854;
extern f32 lbl_803E5858;
extern f32 lbl_803E585C;
extern f32 sqrtf(f32);
void SB_ShipHead_update(int obj) {
    f32 ddx;
    f32 ddy;
    f32 ddz;
    f32 s;
    int player;
    u8 *galleon;
    int state;
    int i;
    int mode;
    SBShipHeadState *hs;
    int proj;
    u8 *setup;
    int msg;
    int start;
    int end;
    int hit;
    f32 px;
    f32 py;
    f32 pz;
    int tmp2[2];
    int tmp3;

    mode = 0;
    player = Obj_GetPlayerObject();
    galleon = *(u8 **)&((GameObject *)obj)->anim.parent;
    if (galleon != 0) {
        state = DBprotection_getCameraState(getSbGalleon());
        if (state == 2) {
            if (Vec_distance((void *)(player + 0x18), (void *)&((GameObject *)obj)->anim.worldPosX) < lbl_803E5840) {
                Sfx_PlayFromObject(obj, 0x312);
            }
            else {
                Sfx_StopObjectChannel(obj, 0x40);
            }
        }
        state = *(int *)(galleon + 0xf4);
        hs = ((GameObject *)obj)->extra;
        if (*(void **)&hs->target == 0) {
            int *arr = (int *)ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++) {
                int o = arr[i];
                if (*(s16 *)(o + 0x46) == 0x8c) {
                    hs->target = o;
                    i = end;
                }
            }
        }
        if (ObjMsg_Pop(obj, &msg, tmp2, &tmp3) != 0) {
            switch (msg) {
            case 0x130002:
                mode = 1;
                break;
            case 0x130003:
                mode = 2;
                break;
            }
        }
        if (((**(int (**)(u8 *))(**(int **)(galleon + 0x68) + 0x28))(galleon) >= 2)
            && (((GameObject *)obj)->unkF8 <= 0) && (((uint)(state - 3) <= 1 || (state == 5)))
            && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            && (*(s16 *)(hit + 0x46) != 0x114)) {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, 0x37);
            hs->health -= 1;
            if (hs->health <= 0) {
                (**(void (**)(u8 *))(**(int **)(galleon + 0x68) + 0x20))(galleon);
                ((GameObject *)obj)->unkF8 = 300;
                ObjHits_DisableObject(obj);
            }
        }
        if (0 < ((GameObject *)obj)->unkF8) {
            ((GameObject *)obj)->unkF8 = ((GameObject *)obj)->unkF8 - framesThisStep;
        }
        if (state == 8) {
            ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 + 1;
            if (10 < ((GameObject *)obj)->unkF4) {
                ((GameObject *)obj)->unkF4 = 0;
            }
        }
        if ((state == 5) && (lbl_803DDC48 != 5)) {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E5834, 0);
            lbl_803DC090 = 0;
        }
        if ((((((GameObject *)obj)->anim.currentMove == 1) && (lbl_803E5844 <= ((GameObject *)obj)->anim.currentMoveProgress))
             && (lbl_803DC090 == 0)) && (Obj_IsLoadingLocked() != 0)) {
            lbl_803DC090 = 1;
            ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 + framesThisStep;
            Sfx_PlayFromObject(obj, 0x38);
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + lbl_803E5848;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.localPosZ - lbl_803E584C;
            Obj_GetWorldPosition(obj, &px, &py, &pz);
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E5848;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.localPosZ + lbl_803E584C;
            setup = Obj_AllocObjectSetup(0x18, 0x114);
            setup[6] = 0xff;
            setup[7] = 0xff;
            setup[4] = 2;
            setup[5] = 1;
            *(f32 *)(setup + 8) = px;
            *(f32 *)(setup + 0xc) = py;
            *(f32 *)(setup + 0x10) = pz;
            proj = Obj_SetupObject(setup, 5, -1, -1, 0);
            ddx = *(f32 *)(player + 0x18) - *(f32 *)(proj + 0xc);
            ddy = (*(f32 *)(player + 0x1c) - lbl_803E5850) - *(f32 *)(proj + 0x10);
            ddz = *(f32 *)(player + 0x20) - *(f32 *)(proj + 0x14);
            s = lbl_803E5850 / sqrtf(ddz * ddz + (ddx * ddx + ddy * ddy));
            *(f32 *)(proj + 0x24) = ddx * s;
            *(f32 *)(proj + 0x28) = ddy * s;
            *(f32 *)(proj + 0x2c) = ddz * s;
            *(int *)(proj + 0xf4) = 0x78;
            *(int *)(proj + 0xf8) = hs->target;
        }
        if ((mode == 1) && (Obj_IsLoadingLocked() != 0)) {
            Sfx_PlayFromObject(obj, 0x38);
            player = Obj_GetPlayerObject();
            setup = Obj_AllocObjectSetup(0x18, 0x138);
            *(f32 *)(setup + 8) = lbl_803E5854 + *(f32 *)(player + 0x18);
            *(f32 *)(setup + 0xc) = lbl_803E5848 + (*(f32 *)(player + 0x1c) + (f32)(int)randomGetRange(-6, 6));
            *(f32 *)(setup + 0x10) = lbl_803E5858 + (*(f32 *)(player + 0x20) + (f32)(int)randomGetRange(-6, 6));
            setup[4] = 2;
            setup[5] = 1;
            setup[6] = 0xff;
            setup[7] = 0xff;
            Obj_SetupObject(setup, 5, -1, -1, 0);
        }
        proj = ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E585C, timeDelta, NULL);
        if ((((GameObject *)obj)->anim.currentMove == 1) && (proj != 0)) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5834, 0);
        }
    }
    lbl_803DDC48 = state;
}


/* Trivial 4b 0-arg blr leaves. */
void SB_Galleon_release(void) {}
void SB_Galleon_initialise(void) {}
void SB_ShipMast_free(void) {}
void SB_ShipMast_hitDetect(void) {}
void SB_ShipMast_init(void) {}
void SB_ShipMast_release(void) {}
void SB_ShipMast_initialise(void) {}

extern f32 lbl_803E586C;
extern f32 lbl_803E5870;
extern f32 lbl_803E5874;
extern f32 lbl_803E5878;

#pragma scheduling off
#pragma peephole off
void SB_ShipMast_update(int *obj) {
    extern u8 framesThisStep;
    int *parent;
    int pf4;
    f32 speed;

    parent = *(int**)&((GameObject *)obj)->anim.parent;
    if (parent == NULL) return;
    pf4 = *(int*)((char*)parent + 0xf4);
    ((GameObject *)obj)->anim.localPosX = lbl_803E586C;
    ((GameObject *)obj)->anim.localPosY = lbl_803E586C;
    ((GameObject *)obj)->anim.localPosZ = lbl_803E586C;
    if (*(s16*)((char*)*(int**)&((GameObject *)obj)->anim.parent + 0x46) == 0x139) {
        if (pf4 >= 0xa && pf4 < 0xd) {
            if (((GameObject *)obj)->anim.currentMove != 0) {
                ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E586C, 0);
            }
            if (pf4 >= 0xc) {
                speed = lbl_803E5870;
            } else {
                speed = lbl_803E5874;
            }
        } else {
            if (((GameObject *)obj)->anim.currentMove != 1) {
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
            }
            speed = lbl_803E5878;
        }
    } else {
        if (((GameObject *)obj)->anim.currentMove != 1) {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
        }
        speed = lbl_803E5878;
    }
    ObjAnim_AdvanceCurrentMove(speed, (f32)(u32)framesThisStep, (int)obj, NULL);
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int SB_Galleon_getExtraSize(void) { return 0xb4; }
int SB_Galleon_getObjectTypeId(void) { return 0x0; }
int SB_Propeller_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getObjectTypeId(void) { return 0x1; }
int SB_ShipMast_getExtraSize(void) { return 0x0; }
int SB_ShipMast_getObjectTypeId(void) { return 0x0; }
int SB_ShipGun_getExtraSize(void) { return 0x10; }

/* sda21 accessors. */
extern u32 lbl_803DDC20;
extern u32 lbl_803DDC40;
u32 getSbGalleon(void) { return lbl_803DDC20; }
u32 fn_801E2570(void) { return lbl_803DDC40; }

/* Pattern wrappers. */
u8 SB_Galleon_render2(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x79); }

/* 16b chained patterns. */
s32 SB_Galleon_func0B(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x2b); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5868;
#pragma peephole off
void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5810); }
void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5868); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void SB_ShipHead_free(int x) { ObjGroup_RemoveObject(x, 0x3); }
#pragma peephole reset
#pragma scheduling reset

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */
void SB_Propeller_hitDetect(int param_1) {
    if (*(s16*)(param_1 + 0x46) != 0x69c) return;
    *(s16*)(param_1 + 4) = *(s16*)(lbl_803DDC40 + 4);
}

/* SB_ShipGun_free: expgfx interface freeObject callback. */
void SB_ShipGun_free(int param_1) {
    (*gExpgfxInterface)->freeSource2((u32)param_1);
}

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */
#pragma peephole off
int SB_Galleon_setScale(int obj) {
    s8 *p = (s8*)((int**)obj)[0xb8/4];
    int s = ((SBGalleonState *)p)->phase;
    if (s != 1) {
        if (s >= 2) {
            Sfx_PlayFromObject(obj, SFXen_diallp_c);
        }
        ((SBGalleonState *)p)->stage = ((SBGalleonState *)p)->stage + 1;
        return 1;
    }
    {
        int t = *(s8 *)&((SBGalleonState *)p)->flightPattern;
        if (t == 0 || t == 1 || t == 2) {
            ((SBGalleonState *)p)->unk7C = ((SBGalleonState *)p)->unk7C + 1;
            return 1;
        }
    }
    return 0;
}
#pragma peephole reset

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */
extern f32 lbl_803E57FC;
extern f32 lbl_803E5800;
extern f32 lbl_803E5804;
extern f32 lbl_803E5808;
extern f32 lbl_803E5738;
extern f32 lbl_803E56F0;
extern f32 lbl_803E56C8;
#pragma peephole off
#pragma scheduling off
void SB_Galleon_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    u8 *p = (u8*)((int**)obj)[0xb8/4];
    struct {
        u8 pad[6];
        u16 mode;
        f32 unused;
        f32 a;
        f32 b;
        f32 c;
    } stk;
    if (visible != 0) {
        if ((s8)((SBGalleonState *)p)->cameraState < 2) {
            stk.mode = (u16)(s32)((SBGalleonState *)p)->wanderA;
            stk.a = lbl_803E5804;
            stk.b = lbl_803E5800;
            stk.c = lbl_803E57FC;
            (*gPartfxInterface)->spawnObject((void *)obj, 0xa3, stk.pad, 2, -1, NULL);
            stk.mode = (u16)(s32)((SBGalleonState *)p)->wanderB;
            stk.a = lbl_803E5808;
            (*gPartfxInterface)->spawnObject((void *)obj, 0xa3, stk.pad, 2, -1, NULL);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E57A4);
    }
}

void SB_Galleon_hitDetect(int obj) {
    int *p = ((int**)obj)[0xb8/4];
    u8 i;
    struct {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;
    if (((SBGalleonState *)p)->sprayActive != 0 && ((SBGalleonState *)p)->linkedActor != 0) {
        stk.a = lbl_803E5738;
        stk.mode = 0xc0a;
        stk.b = lbl_803E56CC;
        stk.c = lbl_803E56F0;
        stk.d = lbl_803E56C8;
        for (i = 0; i < framesThisStep; i = i + 1) {
            (*gPartfxInterface)->spawnObject(
                (void *)((SBGalleonState *)p)->linkedActor, 0x7aa, stk.pad, 2, -1, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset


/*
 * --INFO--
 *
 * Function: SB_Galleon_update
 * EN v1.0 Address: 0x801E21AC
 * EN v1.0 Size: 568b
 */
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern void fn_801DFA28(int obj);
extern void DBprotection_updateShield(int obj);
extern void SCGameBitLatch_Update(u8 *latch, int mask, int a, int b, int bit, int c);
extern MapEventInterface **gMapEventInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
void SB_Galleon_update(int obj) {
    s8 *p = (s8 *)((int **)obj)[0xb8/4];
    *(s8 *)(obj + 0xac) = ((SBGalleonState *)p)->mapLayer;
    fn_801E1588(obj, (int)p);
    if (GameBit_Get(0x75) == 0) {
        (*gMapEventInterface)->setMode(0xb, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 0, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 1, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 5, 1);
        lockLevel(mapGetDirIdx(0xb), 0);
        if ((*gMapEventInterface)->getAnimEvent(*(u8 *)(obj + 0x34), 1) == 0) {
            (*gMapEventInterface)->setAnimEvent(*(u8 *)(obj + 0x34), 1, 1);
        }
        ((GameObject *)obj)->unkF4 = 0;
    }
    else {
        if ((((SBGalleonState *)p)->unk80 == 0) && (*(s8 *)&((SBGalleonState *)p)->cameraState > 0)) {
            *(s8 *)&((SBGalleonState *)p)->unk80 = 1;
        }
        switch (*(s8 *)&((SBGalleonState *)p)->cameraState) {
        case 0:
            fn_801DFA28(obj);
            break;
        case 1:
            (*gObjectTriggerInterface)->runSequence(3, (void *)obj, -1);
            *(s8 *)&((SBGalleonState *)p)->cameraState = 2;
            break;
        case 2:
            DBprotection_updateShield(obj);
            break;
        case 3:
            (*gMapEventInterface)->setMode(0xb, 1);
            *(s8 *)(obj + 0xac) = -1;
            (*gObjectTriggerInterface)->runSequence(2, (void *)obj, -1);
            *(s8 *)&((SBGalleonState *)p)->cameraState = 4;
            break;
        }
        SCGameBitLatch_Update((u8 *)p + 0xb0, 1, -1, -1, 0xa71, 0xa4);
    }
}

/*
 * --INFO--
 *
 * Function: SB_Galleon_init
 * EN v1.0 Address: 0x801E23E4
 * EN v1.0 Size: 388b
 */
extern void objSetSlot(void *obj, int slot);
extern void *textureLoadAsset(int id);
extern int lbl_803DDC18;
extern int lbl_803DDC1C;
extern f32 lbl_803E580C;
void SB_Galleon_init(int obj) {
    int p = *(int *)&((GameObject *)obj)->extra;
    lbl_803DDC20 = obj;
    ObjGroup_AddObject(obj, 3);
    objSetSlot((void *)obj, 0x5a);
    ((GameObject *)obj)->animEventCallback = (void *)SB_Galleon_animEventCallback;
    ((SBGalleonState *)p)->posX = ((GameObject *)obj)->anim.localPosX;
    ((SBGalleonState *)p)->posY = ((GameObject *)obj)->anim.localPosY;
    ((SBGalleonState *)p)->posZ = ((GameObject *)obj)->anim.localPosZ;
    *(u8 *)&((SBGalleonState *)p)->sweepDir = 1;
    ((SBGalleonState *)p)->timer26 = 0xf0;
    ((SBGalleonState *)p)->phaseTimer = 0xf0;
    ((SBGalleonState *)p)->unk79 = 0;
    ((SBGalleonState *)p)->headingLatch = 200;
    ((SBGalleonState *)p)->envfxActs[2] = 0x89;
    ((SBGalleonState *)p)->envfxActs[3] = 0x95;
    ((SBGalleonState *)p)->envfxActs[4] = 0x86;
    ((SBGalleonState *)p)->envfxActs[5] = 0x88;
    ((SBGalleonState *)p)->envfxActs[0] = 0x87;
    ((SBGalleonState *)p)->envfxActs[1] = 0x97;
    ((SBGalleonState *)p)->mapLayer = *(s8 *)(obj + 0xac);
    *(s16 *)obj = 0x4000;
    ((GameObject *)obj)->anim.rotY = 0;
    ((GameObject *)obj)->anim.rotZ = 0;
    lbl_803DDC18 = (int)textureLoadAsset(0x16d);
    lbl_803DDC1C = (int)textureLoadAsset(0x89);
    ((SBGalleonState *)p)->unk84 = 100;
    (*gMapEventInterface)->setMode(*(s8 *)(obj + 0xac), 1);
    getLActions(obj, obj, 0x58, 0, 0, 0);
    ((SBGalleonState *)p)->wanderTimerA = lbl_803E56CC;
    ((SBGalleonState *)p)->wanderTimerB = lbl_803E580C;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 0x1800;
    setDrawLights(0);
    ((SBGalleonState *)p)->musicIdA = 0x92;
    ((SBGalleonState *)p)->musicIdB = 0x91;
    Music_Trigger(((SBGalleonState *)p)->musicIdB, 1);
}


/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */
extern void textureFree(void *tex);
void SB_Galleon_free(int obj, int p2) {
    u8 *p = (u8*)((int**)obj)[0xb8/4];
    if ((void*)lbl_803DDC18 != NULL) {
        textureFree((void*)lbl_803DDC18);
        lbl_803DDC18 = 0;
    }
    if ((void*)lbl_803DDC1C != NULL) {
        textureFree((void*)lbl_803DDC1C);
        lbl_803DDC1C = 0;
    }
    ObjGroup_RemoveObject(obj, 3);
    if (((SBGalleonState *)p)->unk80 != 0 && p2 == 0) {
        ((SBGalleonState *)p)->unk80 = 0;
    }
    lbl_803DDC20 = 0;
    Music_Trigger(((SBGalleonState *)p)->musicIdB, 0);
    Music_Trigger(((SBGalleonState *)p)->musicIdA, 0);
    GameBit_Set(0xac8, 1);
}

/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */
extern void ObjMsg_AllocQueue(int obj, int n);
extern f32 lbl_803E5830;
extern f32 lbl_803E5838;
#pragma scheduling off
#pragma peephole off
void SB_ShipHead_init(int obj) {
    f32 *p = (f32*)((int**)obj)[0xb8/4];
    ObjGroup_AddObject(obj, 3);
    ObjMsg_AllocQueue(obj, 10);
    ((SBShipHeadState *)p)->health = 4;
    ((SBShipHeadState *)p)->swayB = ((SBShipHeadState *)p)->swayB + lbl_803E5830;
    ((SBShipHeadState *)p)->swayA = ((SBShipHeadState *)p)->swayA + lbl_803E5838;
}
#pragma peephole reset
#pragma scheduling reset

/* SB_ShipGun_render: conditional render with multiple flag checks. */
extern f32 lbl_803E5888;
#pragma scheduling off
#pragma peephole off
void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    void *o30 = *(void**)&((GameObject *)obj)->anim.parent;
    s8 *p = ((GameObject *)obj)->extra;
    s32 v;
    if (o30 != NULL) {
        if (*(s16*)((char*)o30 + 0x46) == 0x139) return;
    }
    v = visible;
    if (v != 0 && p[0xc] != 0 && ((u8*)p)[0xd] != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5888);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */
#pragma peephole off
#pragma scheduling off
int SB_Galleon_modelMtxFn(int *obj) {
    u8 *p = (u8*)((int**)obj)[0xb8/4];
    u8 b = *(u8 *)&((SBGalleonState *)p)->phase;
    if ((s8)b == 0) {
        if (((SBGalleonState *)p)->timer26 > 0) return -2;
    }
    if ((s8)b == 1) {
        int t = (s8)((SBGalleonState *)p)->flightPattern;
        if (t == 2) return -1;
        if (t == 3) return -1;
        if (t == 5) return -1;
    }
    return (s8)b;
}
#pragma scheduling reset
#pragma peephole reset

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */
#pragma peephole off
int SB_Galleon_func0E(int *obj) {
    register s8 *p = (s8*)((int**)obj)[0xb8/4];
    s8 phase;
    int wrappedPhase;
    if (((SBGalleonState *)p)->phase == 1) {
        phase = ((SBGalleonState *)p)->unk7C;
        if (phase >= 5) {
            wrappedPhase = phase - 5;
        } else {
            wrappedPhase = phase;
        }
        return (6 - wrappedPhase) * 0x5a;
    }
    return 0x640;
}
#pragma peephole reset
