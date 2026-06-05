#include "ghidra_import.h"
#include "main/dll/crackanim.h"
#include "main/audio/sfx_ids.h"


extern undefined8 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017a78();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 FUN_80039520();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8017db40();
extern undefined4 FUN_8017de58();
extern int FUN_8017e15c();
extern int FUN_8017e3c0();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294d60();

extern u8 *Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void playerAddHealth(u8 *player, int v);
extern void itemPickupDoParticleFx(int obj, f32 f1, int p3, int p4);
extern u32 randomGetRange(int min, int max);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern int *objFindTexture(int obj, int textureId, int modelIdx);

extern undefined4* gSHthorntailAnimationInterface;
extern undefined4* gPartfxInterface;
extern f64 lbl_803E3820;
extern f32 timeDelta;
extern f32 lbl_803E37C8;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37DC;
extern f32 lbl_803E3828;
extern f32 lbl_803E382C;
extern f32 lbl_803E3830;
extern f32 lbl_803E3834;
extern f32 lbl_803E3838;
extern f32 lbl_803E37C8;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E37D4;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3814;
extern f32 lbl_803E3818;

/*
 * --INFO--
 *
 * Function: appleontree_update
 * EN v1.0 Address: 0x8017E1A0
 * EN v1.0 Size: 2460b
 * EN v1.1 Address: 0x8017E6F8
 * EN v1.1 Size: 1988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void appleontree_update(int param_1)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  f32 fVar10;
  f32 fVar11;
  f32 fVar12;
  f32 fVar13;
  int local_78;
  undefined auStack_74 [4];

  puVar2 = (undefined2 *)param_1;
  iVar8 = *(int *)(puVar2 + 0x5c);
  iVar7 = *(int *)(puVar2 + 0x26);
  local_78 = 0;
  if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) {
    while (iVar3 = ObjMsg_Pop((int)puVar2,&local_78,(uint *)0x0,(uint *)0x0), iVar3 != 0) {
      switch (local_78) {
      case 0x7000b: {
        playerAddHealth(Obj_GetPlayerObject(), (int)*(u16 *)(iVar8 + 0x38));
        itemPickupDoParticleFx((int)puVar2, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject((int)puVar2, SFXen_waterblock_stop);
        iVar3 = *(int *)(puVar2 + 0x5c);
        if (*(s16 *)((u8 *)puVar2 + 6) & 0x2000) {
          Obj_FreeObject((int)puVar2);
        }
        else {
          if (*(void **)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) & ~4;
      }
      }
    }
    if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) goto switchD_8017e864_caseD_7;
  }
  if ((*(byte *)(iVar8 + 0x5a) & 2) == 0) {
    *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + timeDelta;
    fVar1 = *(float *)(iVar8 + 0xc);
    *(float *)(iVar8 + 0xc) = fVar1 + timeDelta;
    fVar11 = *(float *)(iVar8 + 8);
    fVar13 = fVar11 / *(float *)(iVar8 + 4);
    switch(*(undefined *)(iVar8 + 0x3a)) {
    case 0:
      iVar3 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar3 != 0) ||
         ((*(short *)(iVar7 + 0x26) != -1 &&
          (uVar5 = GameBit_Get((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (*(void (**)(undefined2 *, int, int, int, int, int))(*gPartfxInterface + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(void **)(puVar2 + 0x2a) != 0) {
          ObjHits_DisableObject((int)puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = timeDelta;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      else {
        if (fVar13 > *(float *)(iVar8 + 0x10)) {
          *(float *)(puVar2 + 4) = *(float *)(*(int *)(puVar2 + 0x28) + 4);
          *(undefined *)(iVar8 + 0x3a) = 1;
        }
        else {
          iVar7 = *(int *)(puVar2 + 0x5c);
          *(float *)(puVar2 + 4) =
               (*(float *)(iVar7 + 8) / *(float *)(iVar7 + 4)) *
               (lbl_803E37C8 / *(float *)(iVar7 + 0x10)) *
               *(float *)(*(int *)(puVar2 + 0x28) + 4);
        }
      }
      break;
    case 1:
      iVar3 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar3 != 0) ||
         ((*(short *)(iVar7 + 0x26) != -1 &&
          (uVar5 = GameBit_Get((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (*(void (**)(undefined2 *, int, int, int, int, int))(*gPartfxInterface + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(void **)(puVar2 + 0x2a) != 0) {
          ObjHits_DisableObject((int)puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = timeDelta;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      else {
        if (fVar13 > *(float *)(iVar8 + 0x14)) {
          iVar7 = 0;
          do {
            (*(void (**)(undefined2 *, int, int, int, int, int))(*gPartfxInterface + 8))(puVar2,0x55a,0,2,0xffffffff,0);
            iVar7 = iVar7 + 1;
          } while (iVar7 < 8);
          *(undefined *)(iVar8 + 0x3a) = 2;
        }
        else {
          iVar7 = (*(int (**)(void *))(*gSHthorntailAnimationInterface + 0x24))(auStack_74);
          if (iVar7 != 0) {
            FUN_8002fc3c(lbl_803E3804, timeDelta);
          }
          else {
            FUN_8002fc3c(lbl_803E3808, timeDelta);
          }
        }
      }
      break;
    case 2:
      if (fVar13 > *(float *)(iVar8 + 0x18)) {
        iVar3 = *(int *)(puVar2 + 0x5c);
        puVar4 = (undefined4 *)FUN_80039520((int)puVar2,0);
        *puVar4 = 0;
        *(float *)(iVar3 + 0x24) = lbl_803E37C8;
        *(float *)(puVar2 + 4) = *(float *)(*(int *)(puVar2 + 0x28) + 4);
        FUN_80017a78((int)puVar2,1);
        *(undefined *)(iVar8 + 0x3a) = 3;
      }
      else {
        iVar3 = *(int *)(puVar2 + 0x5c);
        fVar1 = *(float *)(iVar3 + 8);
        fVar11 = -(*(float *)(iVar3 + 4) * *(float *)(iVar3 + 0x14) - fVar1) /
                 (*(float *)(iVar3 + 4) *
                  (*(float *)(iVar3 + 0x18) - *(float *)(iVar3 + 0x14)));
        fVar1 = fVar1 * fVar1 * fVar1 * fVar1;
        iVar8 = (int)((fVar1 * fVar1) / *(float *)(iVar3 + 0x54));
        piVar6 = (int *)FUN_80039520((int)puVar2,0);
        *piVar6 = 0x100 - iVar8;
        *(float *)(iVar3 + 0x24) = lbl_803E37D0 * fVar11 + lbl_803E37CC;
        *(float *)(puVar2 + 4) = *(float *)(*(int *)(puVar2 + 0x28) + 4) * *(float *)(iVar3 + 0x24);
        FUN_80017a78((int)puVar2,1);
      }
      iVar8 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar8 != 0) ||
         ((*(short *)(iVar7 + 0x26) != -1 &&
          (uVar5 = GameBit_Get((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
        FUN_8017db40((uint)puVar2,1);
      }
      break;
    case 3:
      *(float *)(iVar8 + 8) = fVar11 - timeDelta;
      if (fVar13 > *(float *)(iVar8 + 0x1c)) {
        FUN_8017db40((uint)puVar2,0);
      }
      else {
        iVar8 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
        if ((iVar8 != 0) ||
           ((*(short *)(iVar7 + 0x26) != -1 &&
            (uVar5 = GameBit_Get((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
          FUN_8017db40((uint)puVar2,2);
        }
      }
      break;
    case 4:
      if (fVar13 > *(float *)(iVar8 + 0x20)) {
        *(undefined *)(iVar8 + 0x3a) = 6;
        *(float *)(iVar8 + 8) = timeDelta;
      }
      else {
        iVar7 = 0;
        iVar3 = 0;
        fVar12 = lbl_803E37D4;
        do {
          f32 t = *(float *)(iVar8 + 0xc);
          if (iVar7 != 0) break;
          fVar11 = t * (*(float *)(iVar8 + 0x40) + *(float *)(iVar8 + 0x3c));
          fVar10 = t * fVar11 + (*(float *)(iVar8 + 0x44) * t + *(float *)(iVar8 + 0x2c));
          if (*(float *)(iVar8 + 0x28) <= fVar12) {
            iVar7 = FUN_8017e15c(fVar10,puVar2,iVar8);
          }
          else {
            iVar7 = FUN_8017e3c0(fVar10,puVar2,iVar8);
          }
          iVar3 = iVar3 + 1;
        } while ((iVar3 == 100) || (iVar3 != 0x66));
        if (lbl_803E37D4 != *(float *)(iVar8 + 0x30)) {
          fVar11 = *(float *)(iVar8 + 0xc) / *(float *)(iVar8 + 0x50);
          *puVar2 = (short)(int)((f32)*(s16 *)(iVar8 + 0x48) * fVar11);
          puVar2[1] = (short)(int)((f32)*(s16 *)(iVar8 + 0x4a) * fVar11);
          puVar2[2] = (short)(int)((f32)*(s16 *)(iVar8 + 0x4c) * fVar11);
        }
        piVar6 = (int *)FUN_80039520((int)puVar2,0);
        *piVar6 = (int)(lbl_803E380C * fVar13);
        FUN_8017de58((uint)puVar2);
      }
      break;
    case 5:
      if (lbl_803E3810 < fVar11) {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if (*(s16 *)((u8 *)puVar2 + 6) & 0x2000) {
          Obj_FreeObject((int)puVar2);
        }
        else {
          if (*(void **)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
      }
      break;
    case 6:
      fVar13 = lbl_803E3814;
      if (fVar11 > fVar13) {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if (*(s16 *)((u8 *)puVar2 + 6) & 0x2000) {
          Obj_FreeObject((int)puVar2);
        }
        else {
          if (*(void **)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
      }
      else {
        iVar7 = (int)(lbl_803E3818 * fVar11 / fVar13);
        *(char *)(puVar2 + 0x1b) = -1 - (char)iVar7;
        FUN_8017de58((uint)puVar2);
      }
    }
  }
switchD_8017e864_caseD_7:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: appleontree_init
 * EN v1.0 Address: 0x8017E964
 * EN v1.0 Size: 684b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void appleontree_init(int obj, int def)
{
    int state;
    f32 zeroScale;
    f32 timeScale;
    f32 progress;
    int eventBit;
    int *texture;

    state = *(int *)(obj + 0xb8);

    *(u32 *)(state + 0x00) = *(u32 *)(def + 0x18);
    *(f32 *)(state + 0x04) = (f32)*(u16 *)(def + 0x1c);
    *(f32 *)(state + 0x08) = (f32)*(u16 *)(def + 0x1e);
    *(f32 *)(state + 0x10) = (f32)*(u8 *)(def + 0x20) / lbl_803E3828;
    *(f32 *)(state + 0x14) = *(f32 *)(state + 0x10) + (f32)*(u8 *)(def + 0x21) / lbl_803E3828;
    *(f32 *)(state + 0x18) = *(f32 *)(state + 0x14) + (f32)*(u8 *)(def + 0x22) / lbl_803E3828;
    *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x18) + (f32)*(u8 *)(def + 0x23) / lbl_803E3828;
    *(f32 *)(state + 0x20) = (f32)*(u8 *)(def + 0x24) / lbl_803E3828;
    *(f32 *)(state + 0x28) = (f32)*(s8 *)(def + 0x25) / lbl_803E3828;
    *(f32 *)(state + 0x28) = *(f32 *)(state + 0x28) * lbl_803E37DC;
    *(f32 *)(state + 0x24) = lbl_803E37C8;
    *(u16 *)(state + 0x38) = 0;
    zeroScale = lbl_803E37D4;
    *(f32 *)(state + 0x3c) = zeroScale;
    *(f32 *)(state + 0x40) = lbl_803E382C;
    *(f32 *)(state + 0x44) = zeroScale;

    timeScale = *(f32 *)(state + 0x04) * *(f32 *)(state + 0x18);
    timeScale *= timeScale;
    timeScale *= timeScale;
    *(f32 *)(state + 0x54) = (timeScale * timeScale) * lbl_803E3830;

    *(s16 *)(obj + 0x00) = (s16)randomGetRange(-0x8000, 0x7fff);
    *(f32 *)(obj + 0x08) = lbl_803E3834;
    Obj_SetActiveModelIndex(obj, 0);

    eventBit = *(s16 *)(def + 0x26);
    if ((eventBit != -1) && (GameBit_Get(eventBit) != 0)) {
        *(f32 *)(state + 0x08) = lbl_803E3838;
        *(u8 *)(state + 0x3a) = 6;
    } else {
        progress = *(f32 *)(state + 0x08) / *(f32 *)(state + 0x04);
        if (progress < *(f32 *)(state + 0x10)) {
            *(u8 *)(state + 0x3a) = 0;
        } else if (progress < *(f32 *)(state + 0x14)) {
            *(f32 *)(obj + 0x08) = *(f32 *)(*(int *)(obj + 0x50) + 4);
            *(u8 *)(state + 0x3a) = 1;
        } else if (progress < *(f32 *)(state + 0x18)) {
            *(u8 *)(state + 0x3a) = 2;
        } else {
            state = *(int *)(obj + 0xb8);
            texture = objFindTexture(obj, 0, 0);
            *texture = 0;
            *(f32 *)(state + 0x24) = lbl_803E37C8;
            *(f32 *)(obj + 0x08) = *(f32 *)(*(int *)(obj + 0x50) + 4);
            Obj_SetActiveModelIndex(obj, 1);
            *(u8 *)(state + 0x3a) = 3;
        }
    }

    ObjMsg_AllocQueue(obj, 2);
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void dll_FC_free_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_FC_getExtraSize_ret_8(void) { return 0x8; }
int dll_FC_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3848;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3848); }
#pragma peephole reset

extern void dll_FC_initialise_nop(void);
extern void dll_FC_release_nop(void);
extern void dll_FC_init(void);
extern void dll_FC_update(void);
extern void dll_FC_hitDetect(int *obj);

extern void objRenderFn_80041018(int *obj);
#pragma peephole off
void dll_FC_hitDetect(int *obj) {
    int *state = (int *)obj[0x50/4];
    if (((u32)state[0x44/4] & 1u) == 0u) return;
    if (*(void**)((char*)obj + 0x74) == NULL) return;
    objRenderFn_80041018(obj);
}
#pragma peephole reset

ObjectDescriptor gDllFCObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};
