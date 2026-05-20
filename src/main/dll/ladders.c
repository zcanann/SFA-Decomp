#include "ghidra_import.h"
#include "main/dll/ladders.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern double FUN_80017714();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_DisableObject();
extern void* ObjGroup_GetObjects();
extern int ObjHits_PollPriorityHitWithCooldown();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_8016157c();
extern undefined4 FUN_801615d4();
extern undefined4 FUN_80161708();
extern undefined4 FUN_80161920();
extern undefined4 FUN_80161984();
extern undefined4 FUN_80161a8c();
extern undefined4 FUN_80161c08();
extern undefined4 FUN_80161d30();
extern undefined4 FUN_80161ea0();
extern undefined4 FUN_80161f0c();
extern undefined4 FUN_801620c0();
extern undefined4 FUN_8016228c();
extern undefined4 FUN_80162450();
extern undefined4 FUN_801628c4();
extern undefined4 FUN_80162b78();
extern undefined4 FUN_80162ec0();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_80320d30;
extern undefined4 DAT_80320da8;
extern undefined4 DAT_803ad258;
extern undefined4 DAT_803ad25c;
extern undefined4 DAT_803ad260;
extern undefined4 DAT_803ad264;
extern undefined4 DAT_803ad268;
extern undefined4 DAT_803ad26c;
extern undefined4 DAT_803ad270;
extern undefined4 DAT_803ad274;
extern undefined4 DAT_803ad278;
extern undefined4 DAT_803ad27c;
extern undefined4 DAT_803ad280;
extern undefined4 DAT_803ad284;
extern undefined4 DAT_803ad288;
extern undefined4 DAT_803ad28c;
extern undefined4 DAT_803ad290;
extern undefined4 DAT_803ad294;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de700;
extern f64 DOUBLE_803e3ba8;
extern f32 lbl_803DC074;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BCC;
extern f32 lbl_803E3BD0;
extern f32 lbl_803E3BD8;
extern f32 lbl_803E3BE0;
extern f32 lbl_803E3BE4;
extern f32 lbl_803E3BE8;
extern f32 lbl_803E3BEC;
extern f32 lbl_803E3BF0;

/*
 * --INFO--
 *
 * Function: cannonclaw_update
 * EN v1.0 Address: 0x801630EC
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801630F0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Actual cannonclaw_update is 188b — trigger-once cannon-arm awakener.
 * The 668b "Ghidra body" was misattributed; replaced with the right one. */
extern void getTrickyObject(void);
extern void* ObjList_FindObjectById(int id);
extern void ObjAnim_SetCurrentMove(void* obj, int move, f32 weight, int flag);
extern void ObjAnim_AdvanceCurrentMove(void* obj, int flag, f32 weight, f32 dt);
extern f32 timeDelta;
extern f32 lbl_803E2F34;
extern f32 lbl_803E2F38;
#pragma scheduling off
void cannonclaw_update(u8* obj)
{
    u8* trickyState;
    getTrickyObject();
    trickyState = (u8*)ObjList_FindObjectById(0x1723);
    if (*(s32*)(obj + 0xf4) != 0) return;
    if (*(s16*)(obj + 0xa0) != 0x208) {
        ObjAnim_SetCurrentMove(obj, 0x208, lbl_803E2F34, 0);
    }
    ObjAnim_AdvanceCurrentMove(obj, 0, lbl_803E2F38, timeDelta);
    if (trickyState == NULL) return;
    if (GameBit_Get(*(s16*)(*(u8**)(trickyState + 0x4c) + 0x1a)) == 0) return;
    *(s32*)(obj + 0xf4) = 1;
    *(u8*)(obj + 0xaf) = (u8)(*(u8*)(obj + 0xaf) | 0x8);
    ObjHits_DisableObject(obj);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80163388
 * EN v1.0 Address: 0x80163388
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80163390
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163388(int param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016338c
 * EN v1.0 Address: 0x8016338C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8016344C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016338c(void)
{
  FUN_801633ac();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801633ac
 * EN v1.0 Address: 0x801633AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016346C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633ac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801633b0
 * EN v1.0 Address: 0x801633B0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80163554
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633b0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801633e4
 * EN v1.0 Address: 0x801633E4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80163598
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  
  FUN_80017a90();
  iVar1 = FUN_80017af8(0x1723);
  if (*(int *)(param_9 + 0xf4) == 0) {
    if (*(short *)(param_9 + 0xa0) != 0x208) {
      FUN_800305f8((double)lbl_803E3BCC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x208,0,param_12,param_13,param_14,param_15,param_16);
    }
    FUN_8002fc3c((double)lbl_803E3BD0,(double)lbl_803DC074);
    if ((iVar1 != 0) &&
       (uVar2 = GameBit_Get((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1a)), uVar2 != 0)) {
      *(undefined4 *)(param_9 + 0xf4) = 1;
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      ObjHits_DisableObject(param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163544
 * EN v1.0 Address: 0x80163544
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x80163674
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163544(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  undefined4 uVar8;
  int iVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int unaff_r29;
  int iVar11;
  int iVar12;
  double dVar13;
  undefined auStack_28 [4];
  int local_24;
  int local_20 [8];
  
  iVar4 = FUN_80286840();
  iVar12 = *(int *)(iVar4 + 0xb8);
  iVar11 = *(int *)(iVar4 + 0x4c);
  sVar1 = *(short *)(iVar4 + 0x46);
  if (sVar1 == 0x4b9) {
    unaff_r29 = 0x4ba;
  }
  else if (sVar1 < 0x4b9) {
    if (sVar1 == 0x3fd) {
      unaff_r29 = 0x3fb;
    }
    else if ((sVar1 < 0x3fd) && (sVar1 == 0x28d)) {
      iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
      if (iVar5 == 0) goto LAB_80163950;
      unaff_r29 = 0x39d;
    }
  }
  else if (sVar1 == 0x4be) {
    unaff_r29 = 0x4c1;
  }
  local_20[0] = 0;
  iVar10 = -1;
  iVar5 = iVar12;
  while ((local_20[0] < (int)(uint)*(byte *)(iVar12 + 0x50) && (iVar10 == -1))) {
    if (*(int *)(iVar5 + 0xc) == 0) {
      iVar10 = local_20[0];
    }
    iVar5 = iVar5 + 4;
    local_20[0] = local_20[0] + 1;
  }
  if (iVar10 != -1) {
    iVar5 = FUN_80017b00(local_20,&local_24);
    iVar9 = 0;
    while (local_20[0] < local_24) {
      iVar3 = local_20[0] + 1;
      iVar2 = local_20[0] * 4;
      local_20[0] = iVar3;
      if (unaff_r29 == *(short *)(*(int *)(iVar5 + iVar2) + 0x46)) {
        iVar9 = iVar9 + 1;
      }
    }
    if ((iVar9 < 7) && (uVar6 = FUN_80017ae8(), (uVar6 & 0xff) != 0)) {
      puVar7 = FUN_80017aa4(0x20,(short)unaff_r29);
      iVar5 = iVar12 + iVar10 * 0xc;
      *(float *)(puVar7 + 4) = *(float *)(iVar4 + 0xc) + *(float *)(iVar5 + 0x1c);
      *(float *)(puVar7 + 6) = *(float *)(iVar4 + 0x10) + *(float *)(iVar5 + 0x20);
      dVar13 = (double)*(float *)(iVar4 + 0x14);
      *(float *)(puVar7 + 8) = (float)(dVar13 + (double)*(float *)(iVar5 + 0x24));
      *(undefined *)(puVar7 + 2) = *(undefined *)(iVar11 + 4);
      *(undefined *)((int)puVar7 + 5) = *(undefined *)(iVar11 + 5);
      *(undefined *)(puVar7 + 3) = *(undefined *)(iVar11 + 6);
      *(undefined *)((int)puVar7 + 7) = *(undefined *)(iVar11 + 7);
      *(float *)(puVar7 + 0xe) = lbl_803E3BD8;
      if (((*(byte *)(iVar12 + 0x4c) & 1) != 0) &&
         ((*(int *)(*(int *)(iVar4 + 0x4c) + 0x14) == 0x292c && (*(short *)(iVar12 + 0x4e) == 6))))
      {
        *(undefined *)((int)puVar7 + 0x1b) = 1;
        iVar11 = FUN_80017b00(local_20,&local_24);
        for (; local_20[0] < local_24; local_20[0] = local_20[0] + 1) {
          iVar5 = *(int *)(iVar11 + local_20[0] * 4);
          if (*(short *)(iVar5 + 0x46) == 0x27f) {
            *(undefined4 *)(puVar7 + 4) = *(undefined4 *)(iVar5 + 0xc);
            *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x10)
            ;
            *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x14)
            ;
            local_20[0] = local_24;
          }
        }
      }
      uVar8 = FUN_80017ae4(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7,5,
                           *(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30),in_r8,
                           in_r9,in_r10);
      iVar11 = iVar12 + iVar10 * 4;
      *(undefined4 *)(iVar11 + 0xc) = uVar8;
      (**(code **)(**(int **)(*(int *)(iVar11 + 0xc) + 0x68) + 0x24))
                ((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
      *(short *)(iVar12 + 0x4e) = *(short *)(iVar12 + 0x4e) + 1;
    }
  }
LAB_80163950:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801638bc
 * EN v1.0 Address: 0x801638BC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801639B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638bc(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801638e4
 * EN v1.0 Address: 0x801638E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801639EC
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638e4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801638e8
 * EN v1.0 Address: 0x801638E8
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80163B9C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638e8(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  ushort uVar2;
  ushort *puVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  int unaff_r30;
  uint uVar7;
  float *pfVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  pfVar8 = *(float **)(puVar3 + 0x5c);
  *pfVar8 = lbl_803E3BE0;
  *(ushort *)(pfVar8 + 2) = (ushort)*(byte *)(iVar4 + 0x1b) << 1;
  *(undefined *)(pfVar8 + 0x13) = *(undefined *)(iVar4 + 0x23);
  puVar3[2] = (*(byte *)(iVar4 + 0x18) - 0x7f) * 0x80;
  puVar3[1] = (*(byte *)(iVar4 + 0x19) - 0x7f) * 0x80;
  *puVar3 = (ushort)*(byte *)(iVar4 + 0x1a) << 8;
  *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar4 + 0x1c);
  fVar1 = *(float *)(puVar3 + 4);
  ObjHitbox_SetCapsuleBounds((int)puVar3,(short)(int)(lbl_803E3BE4 * fVar1),(short)(int)(lbl_803E3BE8 * fVar1)
               ,(short)(int)(lbl_803E3BEC * fVar1));
  uVar2 = puVar3[0x23];
  if (uVar2 != 0x4b9) {
    if ((short)uVar2 < 0x4b9) {
      if (uVar2 == 0x3fd) {
        *(undefined *)(pfVar8 + 0x14) = 3;
        unaff_r30 = 1;
        goto LAB_80163cb0;
      }
      if ((0x3fc < (short)uVar2) || (uVar2 != 0x28d)) goto LAB_80163cb0;
    }
    else if (uVar2 != 0x4be) goto LAB_80163cb0;
  }
  *(undefined *)(pfVar8 + 0x14) = 3;
  unaff_r30 = 0;
LAB_80163cb0:
  if (param_3 == 0) {
    uVar7 = unaff_r30 * 0x30 + 0x80320e38;
    pfVar5 = pfVar8;
    pfVar6 = pfVar8;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar8 + 0x14); iVar4 = iVar4 + 1) {
      pfVar6[3] = 0.0;
      FUN_80003494((uint)(pfVar5 + 7),uVar7,0xc);
      pfVar5[7] = pfVar5[7] * *(float *)(puVar3 + 4);
      pfVar5[8] = pfVar5[8] * *(float *)(puVar3 + 4);
      pfVar5[9] = pfVar5[9] * *(float *)(puVar3 + 4);
      FUN_80017748(puVar3,pfVar5 + 7);
      pfVar6 = pfVar6 + 1;
      uVar7 = uVar7 + 0xc;
      pfVar5 = pfVar5 + 3;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163ac8
 * EN v1.0 Address: 0x80163AC8
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x80163D68
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80163ac8(float *param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  int local_28 [2];
  
  dVar6 = (double)lbl_803E3BF0;
  iVar3 = 0;
  piVar1 = ObjGroup_GetObjects(0x31,local_28);
  for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
    iVar2 = *piVar1;
    if (((*(short *)(iVar2 + 0x46) == 0x3fb) && (1 < *(byte *)(*(int *)(iVar2 + 0xb8) + 0x278))) &&
       (dVar5 = FUN_80017714((float *)(iVar2 + 0x18),param_1), dVar5 < dVar6)) {
      iVar3 = *piVar1;
      dVar6 = dVar5;
    }
    piVar1 = piVar1 + 1;
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80163b8c
 * EN v1.0 Address: 0x80163B8C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80163E2C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163b8c(int param_1)
{
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0x278) = 7;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void cannonclaw_release(void) {}
void cannonclaw_initialise(void) {}
void tumbleweedbush_free(void) {}
void tumbleweedbush_hitDetect(void) {}
void tumbleweedbush_release(void) {}
void tumbleweedbush_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int tumbleweedbush_getExtraSize(void) { return 0x54; }
int tumbleweedbush_func08(void) { return 0x0; }

/* 16b chained patterns. */
#pragma scheduling off
#pragma peephole off
void fn_80163980(int *obj) { u8 v = 0x7; *((u8*)((int**)obj)[0xb8/4] + 0x278) = v; }
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E2F44;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E2F44); }
#pragma peephole reset

/* byte-to-short shift8 pattern. */
#pragma peephole off
void cannonclaw_init(s16 *dst, void* src) { s8 v = *((s8*)src + 0x28); s16 t = v << 8; *dst = t; }
#pragma peephole reset

/* tumbleweedbush_setScale: scan the sub-array at obj->_b8 (sub[0x50] entries
 * of 4 bytes each), zeroing every slot whose +0xc word matches `match`. */
#pragma scheduling off
void tumbleweedbush_setScale(u8* obj, void* match) {
    u8* sub = *(u8**)(obj + 0xb8);
    int i = 0;
    void** p = (void**)sub;
    while (i < (int)sub[0x50]) {
        if (*(void**)((char*)p + 0xc) == match) {
            *(void**)((char*)p + 0xc) = NULL;
        }
        p = (void**)((char*)p + 4);
        i++;
    }
}
#pragma scheduling reset

extern void tumbleweedbush_update(void);
extern void tumbleweedbush_init(void);

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_func08,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};
