#include "main/audio/sfx_ids.h"
#include "main/dll/lightning.h"
#include "main/dll/pushable.h"
#include "main/objanim_internal.h"
#include "main/game_object.h"

#pragma peephole off
#pragma scheduling off
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void playerAddRemoveMagic(int player, int amount);
extern void OSReport(const char *fmt, ...);
extern f32 getXZDistance(void *a, void *b);
extern int fn_8029622C(int player);
extern u8 framesThisStep;
extern char sMagicDustCollectedMessage[];
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern int Obj_GetActiveModel(int obj);
extern u16 lbl_803E34A8;
extern u16 lbl_803E34AC;
extern u8 lbl_80320CB8[];
extern f32 lbl_803E34E4;
extern f32 lbl_803E34E8;
extern f32 lbl_803E34EC;
extern f32 lbl_803E34F0;
extern f32 lbl_803E34F4;
extern f32 lbl_803E34F8;
extern f32 lbl_803E34FC;
extern int *gExpgfxInterface;
extern int *gPartfxInterface;
extern int *gPathControlInterface;
extern f32 timeDelta;
extern f32 lbl_803E34B0;
extern f32 lbl_803E34B4;
extern f32 lbl_803E34B8;
extern f32 lbl_803E34BC;
extern f32 lbl_803E34C0;
extern f32 lbl_803E34C4;
extern f32 lbl_803E34C8;
extern f32 lbl_803E34CC;
extern f32 lbl_803E34D0;
extern f32 lbl_803E34D4;
extern f32 lbl_803E34D8;
extern f32 lbl_803E34DC;
extern f32 lbl_803E34E0;
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a54();
extern undefined4 FUN_80017a70();
extern undefined4 FUN_80017a74();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern void* ObjGroup_GetObjects();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80081118();
extern undefined4 fn_80174BFC();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern u8 *Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);
extern void objMove(f32 a, f32 b, f32 c, int obj);
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294bd4();
extern uint FUN_80294bd8();
extern uint FUN_80294c78();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_80321908;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e4140;
extern undefined4 DAT_803e4144;
extern f64 DOUBLE_803e4198;
extern f64 DOUBLE_803e41b0;
extern f64 DOUBLE_803e41b8;
extern f64 DOUBLE_803e41c8;
extern f64 DOUBLE_803e41d0;
extern f32 lbl_803DC074;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;
extern f32 lbl_803E4160;
extern f32 lbl_803E4164;
extern f32 lbl_803E4168;
extern f32 lbl_803E416C;
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4190;
extern f32 lbl_803E4194;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41C4;

/* magicdust extra block (collectible sparkle state; tail of the pickup record). */
typedef struct MagicDustState {
    u8 unk00[0x6C];
    f32 unk6C;
    u8 unk70[0x25B - 0x70];
    u8 unk25B;
    u8 unk25C[5];
    s8 unk261;
    u8 unk262[6];
    f32 unk268;
    f32 unk26C; /* sparkle scale; reset on collect */
    u16 unk270;
    u16 unk272; /* partfx effect id */
    s16 unk274; /* collect sfx id */
    s16 unk276;
    s16 unk278;
    u8 flags27A; /* bits 8/0x10/0x40 observed; &0xFA clear on collect */
    u8 unk27B;
    u8 unk27C; /* particle color row */
    u8 unk27D[3];
    u16 unk280;
} MagicDustState;

STATIC_ASSERT(offsetof(MagicDustState, flags27A) == 0x27A);

/*
 * --INFO--
 *
 * Function: magicdust_update
 * EN v1.0 Address: 0x801732A4
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x80173750
 * EN v1.1 Size: 2120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void magicdust_update(int obj)
{
  float fVar1;
  short sVar2;
  byte bVar3;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  char local_28;
  char local_27 [3];
  int local_24 [9];
  register int msgId;
  f32 dist;
  
  iVar5 = (int)Obj_GetPlayerObject();
  iVar8 = *(int *)&((GameObject *)obj)->extra;
  msgId = 0x7000b;
  while (iVar6 = ObjMsg_Pop(obj,(uint *)local_24,(uint *)0x0,(uint *)0x0), iVar6 != 0) {
    if (local_24[0] == msgId) {
      iVar6 = *(int *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x18);
      (*(code *)(*gExpgfxInterface + 0x18))(obj);
      itemPickupDoParticleFx(obj,lbl_803E34B0,((MagicDustState *)iVar8)->unk27C,0x28);
      ObjHits_DisableObject(obj);
      Sfx_PlayFromObject(obj,(u16)((MagicDustState *)iVar8)->unk274);
      Sfx_StopFromObject(obj,0x56);
      playerAddRemoveMagic(iVar5,(int)*(s8 *)(iVar6 + 0xb));
      ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A & 0xfa;
      ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 8;
      ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 0x40;
      ((MagicDustState *)iVar8)->unk26C = lbl_803E34B4;
      OSReport(sMagicDustCollectedMessage);
      *(u8 *)(obj + 0x36) = 1;
    }
  }
  if ((((MagicDustState *)iVar8)->flags27A & 0x10) == 0) {
    if (((((MagicDustState *)iVar8)->flags27A & 0x40) == 0) &&
       (getXZDistance((f32 *)(obj + 0x18),(f32 *)(iVar5 + 0x18)) < lbl_803E34B8)) {
      ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 0x10;
      local_28 = '\0';
      (*(code *)(*gPartfxInterface + 8))
                (obj,((MagicDustState *)iVar8)->unk272,0,0x10002,0xffffffff,&local_28);
      local_28 = '\x01';
      (*(code *)(*gPartfxInterface + 8))
                (obj,((MagicDustState *)iVar8)->unk272,0,0x10002,0xffffffff,&local_28);
      local_28 = '\x02';
      (*(code *)(*gPartfxInterface + 8))
                (obj,((MagicDustState *)iVar8)->unk272,0,0x10002,0xffffffff,&local_28);
    }
  }
  else {
    if (getXZDistance((f32 *)(obj + 0x18),(f32 *)(iVar5 + 0x18)) >= lbl_803E34B8) {
      ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A & 0xef;
      (*(code *)(*gExpgfxInterface + 0x18))(obj);
    }
  }
  if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
    if ((((MagicDustState *)iVar8)->flags27A & 2) != 0) {
      *(short *)obj = *(short *)obj + (u16)framesThisStep * 0x100;
      ((MagicDustState *)iVar8)->unk278 -= (u16)framesThisStep;
      if (((MagicDustState *)iVar8)->unk278 < 0) {
        Sfx_PlayFromObject(obj,SFXen_statue_wave);
        uVar7 = randomGetRange(0xf0,300);
        ((MagicDustState *)iVar8)->unk278 = (short)uVar7;
      }
    }
    if (*(uint *)&((GameObject *)obj)->unkC4 != 0) {
      iVar5 = *(int *)(obj + 0x64);
      if ((uint)iVar5 != 0) {
        *(uint *)(iVar5 + 0x30) = *(uint *)(iVar5 + 0x30) | 0x1000;
      }
      (*(code *)(*gPathControlInterface + 0x20))(obj,iVar8);
      goto LAB_80173f80;
    }
    iVar6 = *(int *)(obj + 0x64);
    if ((uint)iVar6 != 0) {
      *(uint *)(iVar6 + 0x30) = *(uint *)(iVar6 + 0x30) & 0xffffefff;
    }
    *(undefined *)&((MagicDustState *)iVar8)->unk25B = 1;
    fVar1 = lbl_803E34BC;
    if ((((MagicDustState *)iVar8)->flags27A & 3) == 0) {
      ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * fVar1;
      ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * fVar1;
      ((GameObject *)obj)->anim.velocityY = -(lbl_803E34C0 * timeDelta - ((GameObject *)obj)->anim.velocityY);
    }
    ((MagicDustState *)iVar8)->unk26C = ((MagicDustState *)iVar8)->unk26C - timeDelta;
    bVar3 = ((MagicDustState *)iVar8)->flags27A;
    if ((bVar3 & 1) == 0) {
      if ((bVar3 & 4) == 0) {
        if (((MagicDustState *)iVar8)->unk26C <= lbl_803E34C4) {
          Obj_FreeObject(obj);
        }
        goto LAB_80173f80;
      }
      if (((MagicDustState *)iVar8)->unk26C <= lbl_803E34C4) {
        ((MagicDustState *)iVar8)->flags27A = bVar3 & 0xfb;
        ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 8;
        ((MagicDustState *)iVar8)->unk26C = lbl_803E34B4;
        (*(code *)(*gExpgfxInterface + 0x18))(obj);
        if (*(int *)&((GameObject *)obj)->anim.parent == 0) {
          for (local_27[0] = '\x1e'; local_27[0] != '\0'; local_27[0] = local_27[0] + -1) {
            (*(code *)(*gPartfxInterface + 8))(obj,((MagicDustState *)iVar8)->unk270,0,1,0xffffffff,local_27);
          }
        }
        *(u8 *)(obj + 0x36) = 1;
        Sfx_PlayFromObject(obj,SFXen_waterblock_wave);
      }
      objMove(((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta,
          ((GameObject *)obj)->anim.velocityZ * timeDelta, obj);
    }
    else {
      if (((MagicDustState *)iVar8)->unk26C <= lbl_803E34C4) {
        ((MagicDustState *)iVar8)->flags27A = bVar3 & 0xfe;
        ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 4;
        ((MagicDustState *)iVar8)->unk26C = lbl_803E34C8;
        *(u8 *)(obj + 0x36) = 0xff;
      }
      if (*(int *)&((GameObject *)obj)->anim.parent == 0) {
        (*(code *)(*gPartfxInterface + 8))(obj,((MagicDustState *)iVar8)->unk270,0,1,0xffffffff,0);
        (*(code *)(*gPartfxInterface + 8))(obj,((MagicDustState *)iVar8)->unk270,0,1,0xffffffff,0);
      }
    }
    if ((((MagicDustState *)iVar8)->flags27A & 3) == 0) {
      (*(code *)(*gPathControlInterface + 0x10))(timeDelta,obj,iVar8);
      (*(code *)(*gPathControlInterface + 0x14))(obj,iVar8);
      (*(code *)(*gPathControlInterface + 0x18))(timeDelta,obj,iVar8);
      if (((MagicDustState *)iVar8)->unk261 != '\0') {
        float vx = -((GameObject *)obj)->anim.velocityX;
        float vy = -((GameObject *)obj)->anim.velocityY;
        float vz = -((GameObject *)obj)->anim.velocityZ;
        float mag = sqrtf(vx*vx + vy*vy + vz*vz);
        if (lbl_803E34CC < mag) {
          Sfx_PlayFromObject(obj,SFXwp_iceywindlp16);
        }
        if (((MagicDustState *)iVar8)->unk6C < lbl_803E34D0) {
          ((GameObject *)obj)->anim.velocityX = -((GameObject *)obj)->anim.velocityX;
          ((GameObject *)obj)->anim.velocityZ = -((GameObject *)obj)->anim.velocityZ;
          fVar1 = lbl_803E34D8;
          ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * lbl_803E34D8;
          ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * fVar1;
        }
        else {
          ((GameObject *)obj)->anim.velocityY = -((GameObject *)obj)->anim.velocityY;
          ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * lbl_803E34D4;
        }
        bVar3 = *(char *)&((MagicDustState *)iVar8)->unk27B + 1;
        ((MagicDustState *)iVar8)->unk27B = bVar3;
        if (5 < bVar3) {
          ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 2;
          fVar1 = lbl_803E34C4;
          ((GameObject *)obj)->anim.velocityX = lbl_803E34C4;
          ((GameObject *)obj)->anim.velocityY = fVar1;
          ((GameObject *)obj)->anim.velocityZ = fVar1;
        }
      }
    }
  }
  if (((((MagicDustState *)iVar8)->flags27A & 0x20) == 0) && ((((MagicDustState *)iVar8)->flags27A & 0x40) == 0)) {
    fVar1 = ((GameObject *)obj)->anim.localPosY - *(float *)(iVar5 + 0x10);
    if (fVar1 < lbl_803E34C4) {
      fVar1 = -fVar1;
    }
    if (fVar1 < lbl_803E34DC) {
      dist = getXZDistance((f32 *)(obj + 0x18),(f32 *)(iVar5 + 0x18));
      fVar1 = lbl_803E34E0 + ((MagicDustState *)iVar8)->unk268;
      if ((dist < fVar1 * fVar1) && (fn_8029622C(iVar5) != 0)) {
        uVar7 = GameBit_Get(0x90d);
        if (uVar7 == 0) {
          *(undefined2 *)&((MagicDustState *)iVar8)->unk280 = 0xffff;
          ObjMsg_SendToObject(iVar5, 0x7000a, obj, iVar8 + 0x280);
          ObjHits_DisableObject(obj);
          GameBit_Set(0x90d,1);
          ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 0x20;
        }
        else {
          iVar6 = *(int *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x18);
          (*(code *)(*gExpgfxInterface + 0x18))(obj);
          itemPickupDoParticleFx(obj,lbl_803E34B0,((MagicDustState *)iVar8)->unk27C,0x28);
          ObjHits_DisableObject(obj);
          Sfx_PlayFromObject(obj,(u16)((MagicDustState *)iVar8)->unk274);
          Sfx_StopFromObject(obj,0x56);
          playerAddRemoveMagic(iVar5,(int)*(s8 *)(iVar6 + 0xb));
          ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A & 0xfa;
          ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 8;
          ((MagicDustState *)iVar8)->flags27A = ((MagicDustState *)iVar8)->flags27A | 0x40;
          ((MagicDustState *)iVar8)->unk26C = lbl_803E34B4;
          OSReport(sMagicDustCollectedMessage);
          *(u8 *)(obj + 0x36) = 1;
        }
      }
    }
  }
LAB_80173f80:
  return;
}

/*
 * --INFO--
 *
 * Function: magicdust_init
 * EN v1.0 Address: 0x80173B84
 * EN v1.0 Size: 1112b
 * EN v1.1 Address: 0x80173F98
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void magicdust_init(int param_1,int param_2)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  f32 ang;
  f32 spd;
  u16 local_50 [2];
  u16 local_54 [2];
  u8 local_58 [4];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar5 = *(int *)&((GameObject *)param_1)->extra;
  local_58[0] = 3;
  local_50[0] = lbl_803E34A8;
  local_54[0] = lbl_803E34AC;
  uVar3 = randomGetRange(0,0xffff);
  spd = (f32)(int)randomGetRange(0x27,0x2c) / lbl_803E34E4;
  ang = (lbl_803E34E8 * (f32)(int)uVar3) / lbl_803E34EC;
  ((GameObject *)param_1)->anim.velocityX = spd * mathSinf(ang);
  ((GameObject *)param_1)->anim.velocityZ = spd * mathCosf(ang);
  ((GameObject *)param_1)->anim.velocityY = (f32)(int)randomGetRange(0x28,0x32) / lbl_803E34F0;
  sVar1 = *(short *)(param_2 + 0x2e);
  if (sVar1 == 1) {
    ((MagicDustState *)iVar5)->flags27A = ((MagicDustState *)iVar5)->flags27A | 1;
    *(undefined *)(param_1 + 0x36) = 1;
  }
  else if (sVar1 == 2) {
    ((MagicDustState *)iVar5)->flags27A = ((MagicDustState *)iVar5)->flags27A | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    if (*(uint *)&((GameObject *)param_1)->anim.hitReactState != 0) {
      ObjHits_DisableObject(param_1);
    }
    iVar4 = (int)Obj_GetPlayerObject();
    fVar2 = lbl_803E34F4;
    ((GameObject *)param_1)->anim.velocityX =
         (*(float *)(iVar4 + 0xc) - ((GameObject *)param_1)->anim.localPosX) / lbl_803E34F4;
    ((GameObject *)param_1)->anim.velocityY = (*(float *)(iVar4 + 0x10) - ((GameObject *)param_1)->anim.localPosY) / fVar2;
    ((GameObject *)param_1)->anim.velocityZ = (*(float *)(iVar4 + 0x14) - ((GameObject *)param_1)->anim.localPosZ) / fVar2;
  }
  else if (sVar1 == 3) {
    ((MagicDustState *)iVar5)->flags27A = ((MagicDustState *)iVar5)->flags27A | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    ((GameObject *)param_1)->anim.velocityY =
         -((f32)(int)randomGetRange(0x8c,0x96) / lbl_803E34F0);
  }
  ((ObjAnimComponent *)param_1)->bankIndex = *(u8 *)(param_2 + 0x26);
  if (((ObjAnimComponent *)param_1)->bankIndex >=
      ((ObjAnimComponent *)param_1)->modelInstance->modelCount) {
    ((ObjAnimComponent *)param_1)->bankIndex = 0;
  }
  if (*(uint *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  iVar4 = Obj_GetActiveModel(param_1);
  sVar1 = ((GameObject *)param_1)->anim.seqId;
  switch (sVar1) {
  case 0x2c4:
    uVar3 = randomGetRange(0,1);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(u8 *)((int)local_50 + uVar3);
    *(undefined2 *)&((MagicDustState *)iVar5)->unk272 = 0x54f;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk270 = 0x54b;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk274 = 0x58;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk276 = 0x5b0;
    *(undefined *)&((MagicDustState *)iVar5)->unk27C = 4;
    break;
  case 0x2cd:
    uVar3 = randomGetRange(0,1);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(u8 *)((int)local_54 + uVar3);
    *(undefined2 *)&((MagicDustState *)iVar5)->unk272 = 0x54e;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk270 = 0x54a;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk274 = 0x59;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk276 = 0x5b1;
    *(undefined *)&((MagicDustState *)iVar5)->unk27C = 1;
    break;
  case 0x2ce:
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 3;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk272 = 0x54d;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk270 = 0x549;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk274 = 0x5a;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk276 = 0x5b2;
    *(undefined *)&((MagicDustState *)iVar5)->unk27C = 2;
    break;
  default:
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 2;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk272 = 0x550;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk270 = 0x54c;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk274 = 0x5b;
    *(undefined2 *)&((MagicDustState *)iVar5)->unk276 = 0x5b3;
    *(undefined *)&((MagicDustState *)iVar5)->unk27C = 6;
    break;
  }
  ((MagicDustState *)iVar5)->unk268 = lbl_803E34F8;
  if ((((GameObject *)param_1)->anim.flags & 0x2000) != 0) {
    (*(code *)(*gPathControlInterface + 4))(iVar5,0,0x40007,0);
    (*(code *)(*gPathControlInterface + 0xc))(iVar5,1,lbl_80320CB8,iVar5 + 0x268,local_58);
    (*(code *)(*gPathControlInterface + 0x20))(param_1,iVar5);
  }
  ((GameObject *)param_1)->unkB0 = ((GameObject *)param_1)->unkB0 | 0x2000;
  if ((((MagicDustState *)iVar5)->flags27A & 1) != 0) {
    ((MagicDustState *)iVar5)->unk26C = lbl_803E34FC;
  }
  else {
    ((MagicDustState *)iVar5)->unk26C = lbl_803E34C8;
    ((MagicDustState *)iVar5)->flags27A = ((MagicDustState *)iVar5)->flags27A | 4;
  }
  ObjMsg_AllocQueue(param_1,1);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80173fdc
 * EN v1.0 Address: 0x80173FDC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017443C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173fdc(int param_1)
{
  FUN_80017a70(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80173ffc
 * EN v1.0 Address: 0x80173FFC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017445C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173ffc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80174024
 * EN v1.0 Address: 0x80174024
 * EN v1.0 Size: 856b
 * EN v1.1 Address: 0x80174490
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80174024(int param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *unaff_r31;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  int local_e8;
  int local_e4 [3];
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  if (((int)*(uint *)(param_1 + 0xf8) < 0) ||
     (uVar2 = GameBit_Get(*(uint *)(param_1 + 0xf8)), *(byte *)(iVar5 + 0x1f) != uVar2)) {
    local_e4[2] = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_e4[1] = 0x43300000;
    dVar7 = (double)FUN_80294964();
    uStack_d4 = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar8 = (double)FUN_80293f90();
    uStack_cc = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar9 = (double)FUN_80294964();
    uStack_c4 = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar10 = (double)FUN_80293f90();
    uStack_bc = (uint)*(byte *)(iVar5 + 0x1a);
    local_c0 = 0x43300000;
    dVar16 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1a)) -
                            DOUBLE_803e41b8);
    uStack_b4 = (uint)*(byte *)(iVar5 + 0x1b) << 1 ^ 0x80000000;
    local_b8 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e41b0);
    uStack_ac = (uint)*(byte *)(iVar5 + 0x1c);
    local_b0 = 0x43300000;
    dVar14 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1c)) -
                            DOUBLE_803e41b8);
    bVar1 = *(byte *)(iVar5 + 0x22);
    if (bVar1 == 1) {
      local_e4[0] = FUN_80017a90();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if (bVar1 == 0) {
      local_e4[0] = FUN_80017a98();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if ((bVar1 < 3) && (unaff_r31 = ObjGroup_GetObjects(5,&local_e8), unaff_r31 == (int *)0x0)) {
      return;
    }
    dVar18 = -dVar16;
    dVar17 = -dVar14;
    for (iVar4 = 0; iVar4 < local_e8; iVar4 = iVar4 + 1) {
      iVar3 = *unaff_r31;
      dVar11 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc));
      dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10));
      dVar13 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14));
      dVar6 = (double)(float)(dVar11 * dVar7 + (double)(float)(dVar13 * dVar8));
      if ((((dVar18 < dVar6) && (dVar6 < dVar16)) &&
          (dVar6 = (double)(float)(-dVar12 * dVar10 +
                                  (double)(float)((double)(float)(-dVar11 * dVar8 +
                                                                 (double)(float)(dVar13 * dVar7)) *
                                                 dVar9)), dVar17 < dVar6)) &&
         (((dVar6 < dVar14 &&
           (dVar6 = (double)(float)(dVar12 * dVar9 + (double)(float)(dVar6 * dVar10)),
           (double)lbl_803E41AC <= dVar6)) && (dVar6 < dVar15)))) {
        bVar1 = *(byte *)(iVar5 + 0x22);
        if (bVar1 != 1) {
          if (bVar1 == 0) {
            uStack_ac = (uint)*(byte *)(iVar5 + 0x1d);
            local_b0 = 0x43300000;
            FUN_80294bd4((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e41b8),
                         iVar3,1);
          }
          else if (bVar1 < 3) {
            (*(code *)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,*(undefined *)(iVar5 + 0x1d));
          }
        }
      }
      unaff_r31 = unaff_r31 + 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017437c
 * EN v1.0 Address: 0x8017437C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80174864
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017437c(int param_1,int param_2)
{
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_80017a74(param_1);
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  if (*(short *)(param_2 + 0x20) < 0) {
    *(undefined4 *)(param_1 + 0xf8) = 0xffffffff;
  }
  else {
    *(int *)(param_1 + 0xf8) = (int)*(short *)(param_2 + 0x20);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801743f0
 * EN v1.0 Address: 0x801743F0
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801748E4
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801743f0(uint param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_80017a98();
  if (((*(ushort *)(param_2 + 0x100) & 0x80) == 0) && (uVar2 = FUN_80294bd8(iVar1,10), uVar2 == 0))
  {
    FUN_80006824(param_1,SFXmn_craterspit11);
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 2;
    if ((*(ushort *)(param_2 + 0x100) & 4) == 0) {
      fn_80174BFC();
    }
    if (*(float *)(param_1 + 0xc) <= lbl_803E41C4 + *(float *)(iVar3 + 8)) {
      GameBit_Set((int)*(short *)(param_2 + 0xac),1);
      *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
      *(float *)(param_1 + 0xc) = (float)((double)*(float *)(iVar3 + 8) - DOUBLE_803e41c8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(float *)(param_1 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar3 + 0x10));
      FUN_80006824(param_1,SFXmn_dimbos26);
    }
    uVar2 = GameBit_Get(0xa1a);
    if (uVar2 != 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
    }
  }
  else {
    FUN_8000680c(param_1,8);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80174524
 * EN v1.0 Address: 0x80174524
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x80174A34
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80174524(int param_1,int param_2)
{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(iVar4 + 0x14);
  if (iVar3 == 0x49b5d) {
    *(undefined *)(param_2 + 0x144) = 0xb;
    ((ObjAnimComponent *)param_1)->bankIndex = 1;
  }
  else if (iVar3 < 0x49b5d) {
    if (iVar3 == 0x49b2c) {
      *(undefined *)(param_2 + 0x144) = 10;
    }
  }
  else if (iVar3 < 0x49b5f) {
    *(undefined *)(param_2 + 0x144) = 0xc;
    ((ObjAnimComponent *)param_1)->bankIndex = 1;
  }
  uVar1 = GameBit_Get((int)*(short *)(iVar4 + 0x18));
  if (uVar1 != 0) {
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
    puVar2 = (undefined4 *)FUN_80039520(param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  return;
}

extern void fn_8002B758(void);

/*
 * --INFO--
 *
 * Function: effectbox_free
 * EN v1.0 Address: 0x80173F90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void effectbox_free(void)
{
  fn_8002B758();
}


/* Trivial 4b 0-arg blr leaves. */
void effectbox_hitDetect(void) {}
void effectbox_release(void) {}
void effectbox_initialise(void) {}

extern void fn_8002B860(int obj);
#pragma scheduling off
#pragma peephole off
void effectbox_init(int obj, int *def) {
    s16 bit;
    u32 v;
    if (*(int *)((char *)obj + 0xF4) == 0) {
        fn_8002B860(obj);
    }
    *(int *)((char *)obj + 0xF4) = 1;
    bit = *(s16 *)((char *)def + 0x20);
    if (bit > -1) {
        *(int *)((char *)obj + 0xF8) = (int)bit;
    } else {
        *(int *)((char *)obj + 0xF8) = -1;
    }
    v = (u32)*(u16 *)((char *)obj + 0xB0) | 0x6000;
    *(u16 *)((char *)obj + 0xB0) = (u16)v;
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3508;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3508); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void fn_80174588(int obj, PushableState *p2)
{
  extern int *objFindTexture(int, int, int);
  int data = *(int *)&((GameObject *)obj)->anim.placementData;

  switch (*(int *)(data + 0x14)) {
    case 0x49B2C:
      p2->requiredHitId = 10;
      break;
    case 0x49B5D:
      p2->requiredHitId = 11;
      ((ObjAnimComponent *)obj)->bankIndex = 1;
      break;
    case 0x49B5E:
      p2->requiredHitId = 12;
      ((ObjAnimComponent *)obj)->bankIndex = 1;
      break;
  }

  if (GameBit_Get(*(s16 *)(data + 0x18)) != 0) {
    int *tex;
    p2->flags = (u16)(p2->flags | 0x80);
    tex = objFindTexture(obj, 0, 0);
    if (tex != NULL) {
      *tex = 256;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

extern void *getTrickyObject(void);
extern void fn_80295918(f32 amount, int obj, int p3);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int fn_80295A04(void *player, int p2);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *dist);
extern int *objFindTexture(int obj, int a, int b);
extern void *Resource_Acquire(int id, int mode);
extern void Resource_Release(void *handle);
extern void fn_80175428(int obj, int p2);
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;
extern f32 lbl_803E352C;
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;
extern f32 lbl_803E3540;
extern f32 lbl_803E3544;
extern f32 lbl_803E3548;
extern f32 lbl_803E354C;
extern f32 lbl_803E3550;
extern f32 lbl_803E3554;
extern f32 lbl_803E3558;
extern f32 lbl_803E355C;
extern f32 lbl_803E3560;
extern f32 lbl_803E3564;
extern f32 lbl_803E3568;
extern f32 lbl_803E356C;
extern f32 lbl_803E3570;
extern f32 lbl_803E3528;

/*
 * --INFO--
 *
 * Function: effectbox_update
 * EN v1.0 Address: 0x80173FE4
 * EN v1.0 Size: 980b
 */
void effectbox_update(int obj)
{
  int def;
  int count;
  int single;
  int *list;
  int i;
  int other;
  f32 sinY;
  f32 cosY;
  f32 sinX;
  f32 cosX;
  f32 extX;
  f32 extYNeg;
  f32 extZ;
  f32 negExtX;
  f32 negExtZ;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 proj;
  int gb;

  def = *(int *)&((GameObject *)obj)->anim.placementData;
  gb = ((GameObject *)obj)->unkF8;
  if ((gb <= -1) || (*(u8 *)(def + 0x1f) != GameBit_Get(gb))) {
    sinY = mathCosf((lbl_803E350C * (f32)-(*(u8 *)(def + 0x18) << 8)) / lbl_803E3510);
    cosY = mathSinf((lbl_803E350C * (f32)-(*(u8 *)(def + 0x18) << 8)) / lbl_803E3510);
    sinX = mathCosf((lbl_803E350C * (f32)-(*(u8 *)(def + 0x19) << 8)) / lbl_803E3510);
    cosX = mathSinf((lbl_803E350C * (f32)-(*(u8 *)(def + 0x19) << 8)) / lbl_803E3510);
    extX = (f32)*(u8 *)(def + 0x1a);
    extYNeg = (f32)-(*(u8 *)(def + 0x1b) << 1);
    extZ = (f32)*(u8 *)(def + 0x1c);
    switch (*(u8 *)(def + 0x22)) {
    case 1:
      single = (int)Obj_GetPlayerObject();
      if (single == 0) {
        return;
      }
      list = &single;
      count = 1;
      break;
    case 0:
      single = (int)getTrickyObject();
      if (single == 0) {
        return;
      }
      list = &single;
      count = 1;
      break;
    case 2:
      list = (int *)ObjGroup_GetObjects(5, &count);
      if (list == NULL) {
        return;
      }
      break;
    }
    negExtX = -extX;
    negExtZ = -extZ;
    for (i = 0; i < count; i++) {
      other = *list;
      dx = *(f32 *)(other + 0xc) - ((GameObject *)obj)->anim.localPosX;
      dy = *(f32 *)(other + 0x10) - ((GameObject *)obj)->anim.localPosY;
      dz = *(f32 *)(other + 0x14) - ((GameObject *)obj)->anim.localPosZ;
      proj = dx * sinY + dz * cosY;
      if ((proj > negExtX) && (proj < extX)) {
        proj = (-dx) * cosY + dz * sinY;
        proj = (-dy) * cosX + proj * sinX;
        if ((proj > negExtZ) && (proj < extZ)) {
          proj = dy * sinX + proj * cosX;
          if ((proj >= lbl_803E3514) && (proj < extYNeg)) {
            switch (*(u8 *)(def + 0x22)) {
            case 1:
              break;
            case 0:
              fn_80295918((f32)*(u8 *)(def + 0x1d), other, 1);
              break;
            case 2:
              (*(code *)(*(int *)(*(int *)(other + 0x68)) + 0x28))(other, *(u8 *)(def + 0x1d));
              break;
            }
          }
        }
      }
      list++;
    }
  }
}

/*
 * --INFO--
 *
 * Function: fn_80174438
 * EN v1.0 Address: 0x80174438
 * EN v1.0 Size: 336b
 */
int fn_80174438(int obj, PushableState *state)
{
  int def;
  void *player;

  def = *(int *)&((GameObject *)obj)->anim.placementData;
  player = Obj_GetPlayerObject();
  if (((state->flags & 0x80) != 0) || (fn_80295A04(player, 10) != 0)) {
    Sfx_StopObjectChannel(obj, 8);
    return 0;
  }
  Sfx_PlayFromObject(obj, 0x66);
  state->flags |= 2;
  if ((state->flags & 4) == 0) {
    fn_80174BFC(obj, state);
  }
  if (((GameObject *)obj)->anim.localPosX <= lbl_803E352C + *(f32 *)(def + 8)) {
    GameBit_Set(state->gameBit, 1);
    state->flags |= 0x80;
    ((GameObject *)obj)->anim.localPosX = (f32)(*(f32 *)(def + 8) - lbl_803E3530);
    ((GameObject *)obj)->anim.localPosY = *(f32 *)(def + 0xc);
    ((GameObject *)obj)->anim.localPosZ = (f32)(lbl_803E3538 + *(f32 *)(def + 0x10));
    Sfx_PlayFromObject(obj, 0x68);
  }
  if (GameBit_Get(0xa1a) != 0) {
    ((GameObject *)obj)->anim.localPosX = *(f32 *)(def + 8);
    ((GameObject *)obj)->anim.localPosY = *(f32 *)(def + 0xc);
    ((GameObject *)obj)->anim.localPosZ = *(f32 *)(def + 0x10);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: fn_80174668
 * EN v1.0 Address: 0x80174668
 * EN v1.0 Size: 1048b
 */
int fn_80174668(int obj, PushableState *state)
{
  u8 flag;
  int *tex;
  f32 dy;
  f32 dx;
  f32 cur;
  f32 bound;
  f32 p1;
  f32 p2;
  f32 dist[2];

  flag = 0;
  dist[0] = lbl_803E3540;
  fn_80175428(obj, 0);
  if (GameBit_Get(state->gameBit) != 0) {
    cur = ((GameObject *)obj)->anim.rootMotionScale;
    bound = lbl_803E3544;
    if (cur > bound) {
      ((GameObject *)obj)->anim.rootMotionScale = -(lbl_803E3548 * timeDelta - ((GameObject *)obj)->anim.rootMotionScale);
      if (((GameObject *)obj)->anim.rootMotionScale <= bound) {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3528;
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E354C;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
      }
    }
    return 1;
  }
  if (state->nearestObj == NULL) {
    state->nearestObj = (void *)ObjGroup_FindNearestObject(0x11, obj, dist);
  }
  if (state->nearestObj == NULL) {
    return 0;
  }
  if (state->eyeOpenAmount < lbl_803E3550) {
    state->eyeOpenAmount = lbl_803E3550;
  }
  dy = *(f32 *)((int)state->nearestObj + 0x14) - ((GameObject *)obj)->anim.localPosZ;
  if (dy < lbl_803E3528) {
    dy = dy * lbl_803E3554;
  }
  cur = state->unk_F0;
  if (cur < lbl_803E3558 + dy) {
    return 0;
  }
  dx = *(f32 *)((int)state->nearestObj + 0xc) - ((GameObject *)obj)->anim.localPosX;
  if (dx < lbl_803E3528) {
    dx = dx * lbl_803E3554;
  }
  if (dx > lbl_803E355C) {
    return 0;
  }
  if ((cur >= lbl_803E3558 + dy) && (cur <= lbl_803E3560 + dy)) {
    flag = 1;
    GameBit_Set(0x1c9, 1);
  }
  tex = (int *)objFindTexture(obj, 0, 0);
  state->blinkPhase = state->blinkStep * timeDelta + state->blinkPhase;
  if (state->blinkPhase >= state->blinkInterval) {
    state->blinkStep = state->blinkStep * lbl_803E3554;
  } else if (state->blinkPhase < lbl_803E3528) {
    state->blinkInterval = lbl_803E3564 * (f32)(int)randomGetRange(0x19, 0x4b);
    state->blinkStep = state->blinkInterval / (f32)(int)randomGetRange(0x28, 0x46);
    state->blinkPhase = lbl_803E3528;
  }
  if (tex != NULL) {
    state->eyeOpenAmount = state->eyeOpenAmount + state->eyeOpenSpeed;
    if (state->eyeOpenAmount >= lbl_803E3568) {
      GameBit_Set(state->gameBit, 1);
      if (flag) {
        GameBit_Set(0x1c9, 0);
      }
      tex = (int *)Resource_Acquire(0x5b, 1);
      (*(code *)(*(int *)(*tex + 4)))(obj, 0x14, 0, 2, -1, 0);
      (*(code *)(*(int *)(*tex + 4)))(obj, 0x14, 0, 2, -1, 0);
      Resource_Release(tex);
      Sfx_PlayFromObject(obj, 0x65);
    } else {
      state->eyePosX = state->eyePosX + state->eyeDriftSpeedX;
      if (state->eyePosX > lbl_803E356C) {
        state->eyePosX = lbl_803E356C;
      } else if (state->eyePosX < lbl_803E3528) {
        state->eyePosX = lbl_803E356C;
      }
      state->eyePosY = state->eyePosY + state->eyeDriftSpeedY;
      if (state->eyePosY > lbl_803E356C) {
        state->eyePosY = lbl_803E356C;
      } else if (state->eyePosY < lbl_803E3528) {
        state->eyePosY = lbl_803E356C;
      }
      p1 = state->eyePosX * (lbl_803E3570 + state->blinkPhase);
      p2 = state->eyePosY * (lbl_803E3570 + state->blinkPhase);
      *(u8 *)((char *)tex + 0xc) = (u8)(int)state->eyeOpenAmount;
      *(u8 *)((char *)tex + 0xd) = (u8)(int)p1;
      *(u8 *)((char *)tex + 0xe) = (u8)(int)p2;
    }
  }
  return 0;
}
