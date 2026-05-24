#include "ghidra_import.h"
#include "main/dll/WM/WMcrystal.h"
#include "main/objanim_update.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800067c0();
extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8011eb10();
extern undefined4 FUN_801dd5e4();
extern undefined4 FUN_80286830();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_80328658;
extern undefined4 DAT_803286b0;
extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e62a8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e6288;
extern f32 FLOAT_803e628c;
extern f32 FLOAT_803e6290;
extern f32 FLOAT_803e6294;
extern f32 FLOAT_803e6298;
extern f32 FLOAT_803e629c;
extern f32 FLOAT_803e62a0;
extern f32 FLOAT_803e62b4;
extern f32 FLOAT_803e62b8;
extern f32 FLOAT_803e62bc;
extern f32 FLOAT_803e62c0;
extern f32 FLOAT_803e62c4;
extern f32 FLOAT_803e62c8;

#define SC_TOTEMPUZZLE_CRYSTAL_OBJECT_TYPE 0x3c1
#define SC_TOTEMPUZZLE_PEER_OBJECT_TYPE 0x282

#define SC_TOTEMPUZZLE_STATE_FLAGS_OFFSET 0x12
#define SC_TOTEMPUZZLE_STATE_STEP_OFFSET 0x10
#define SC_TOTEMPUZZLE_STATE_READY_FLAG 0x2
#define SC_TOTEMPUZZLE_STATE_REVERSED_FLAG 0x1
#define SC_TOTEMPUZZLE_FORWARD_STEP 4
#define SC_TOTEMPUZZLE_REVERSE_STEP 3
#define SC_TOTEMPUZZLE_SOLVED_COUNT 5

#define SC_TOTEMPUZZLE_WRONG_SFX_ID 0x487
#define SC_TOTEMPUZZLE_COMPLETE_SFX_ID 0x7e
#define SC_TOTEMPUZZLE_PROGRESS_SFX_ID 0x409

/*
 * --INFO--
 *
 * Function: sc_totempuzzle_update
 * EN v1.0 Address: 0x801DD46C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801DD798
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_totempuzzle_update(void)
{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  int local_48;
  int local_44;
  undefined auStack_40 [8];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  bVar1 = false;
  iVar8 = 0;
  iVar3 = FUN_80017b00(&local_44,&local_48);
  for (; local_44 < local_48; local_44 = local_44 + 1) {
    puVar6 = *(undefined2 **)(iVar3 + local_44 * 4);
    if (puVar6[0x23] == SC_TOTEMPUZZLE_CRYSTAL_OBJECT_TYPE) {
      iVar7 = *(int *)(puVar6 + 0x5c);
      if ((*(ushort *)(iVar7 + SC_TOTEMPUZZLE_STATE_FLAGS_OFFSET) &
          SC_TOTEMPUZZLE_STATE_READY_FLAG) != 0) {
        if ((*(ushort *)(iVar7 + SC_TOTEMPUZZLE_STATE_FLAGS_OFFSET) &
            SC_TOTEMPUZZLE_STATE_REVERSED_FLAG) == 0) {
          if (*(short *)(iVar7 + SC_TOTEMPUZZLE_STATE_STEP_OFFSET) == SC_TOTEMPUZZLE_FORWARD_STEP) {
            iVar8 = iVar8 + 1;
            if (puVar6 == puVar2) {
              *(f32 *)(iVar5 + 0xc) = FLOAT_803e6288 * (f32)(s32)*(s16 *)(iVar5 + 0x10);
              *puVar2 = (short)(int)*(f32 *)(iVar5 + 0xc);
              bVar1 = true;
            }
          }
          else if (puVar6 == puVar2) {
            FUN_80006824(0,SC_TOTEMPUZZLE_WRONG_SFX_ID);
          }
        }
        else if (*(short *)(iVar7 + SC_TOTEMPUZZLE_STATE_STEP_OFFSET) == SC_TOTEMPUZZLE_REVERSE_STEP) {
          iVar8 = iVar8 + 1;
          if (puVar6 == puVar2) {
            *(f32 *)(iVar5 + 0xc) = FLOAT_803e6288 * (f32)(s32)((int)*(s16 *)(iVar5 + 0x10) + 1);
            *puVar2 = (short)(int)*(f32 *)(iVar5 + 0xc);
            bVar1 = true;
          }
        }
        else if (puVar6 == puVar2) {
          FUN_80006824(0,SC_TOTEMPUZZLE_WRONG_SFX_ID);
        }
      }
    }
  }
  if (bVar1) {
    local_34 = FLOAT_803e628c;
    local_30 = FLOAT_803e6290;
    local_2c = FLOAT_803e628c;
    local_38 = FLOAT_803e6294;
    for (local_44 = 0x14; local_44 != 0; local_44 = local_44 + -1) {
      FUN_800810f8((double)FLOAT_803e6298,(double)FLOAT_803e629c,(double)FLOAT_803e629c,
                   (double)FLOAT_803e62a0,puVar2,7,5,7,100,(int)auStack_40,0);
    }
    puVar4 = (undefined4 *)FUN_80039520((int)puVar2,0);
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = 0x100;
    }
  }
  if (iVar8 == SC_TOTEMPUZZLE_SOLVED_COUNT) {
    if (bVar1) {
      FUN_80006824(0,SC_TOTEMPUZZLE_COMPLETE_SFX_ID);
    }
  }
  else if (bVar1) {
    FUN_80006824(0,SC_TOTEMPUZZLE_PROGRESS_SFX_ID);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6b8
 * EN v1.0 Address: 0x801DD6B8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DDA28
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6b8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6e0
 * EN v1.0 Address: 0x801DD6E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDA5C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6e0(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6e4
 * EN v1.0 Address: 0x801DD6E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDE74
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6e4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: sc_totembond_spawnGameBitOrbs
 * EN v1.0 Address: 0x801DD6E8
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x801DE018
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_totembond_spawnGameBitOrbs(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  
  psVar1 = (short *)FUN_80286830();
  dVar9 = extraout_f1;
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    cVar4 = '\x01';
    iVar7 = 0;
    for (cVar5 = '\0'; cVar5 < '\b'; cVar5 = cVar5 + '\x01') {
      iVar6 = *(int *)(psVar1 + 0x26);
      puVar3 = FUN_80017aa4(0x38,0x27b);
      dVar8 = (double)FUN_80293f90();
      *(float *)(puVar3 + 4) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 6));
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(psVar1 + 8);
      dVar8 = (double)FUN_80294964();
      *(float *)(puVar3 + 8) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 10));
      *(undefined *)(puVar3 + 2) = *(undefined *)(iVar6 + 4);
      *(byte *)((int)puVar3 + 5) = *(byte *)(iVar6 + 5) & 0xfe | 4;
      *(undefined *)(puVar3 + 3) = *(undefined *)(iVar6 + 6);
      *(undefined *)((int)puVar3 + 7) = 0x1e;
      puVar3[0xc] = 0xffff;
      puVar3[0xd] = 0x64c;
      puVar3[0xe] = (&DAT_803286b0)[cVar4];
      puVar3[0x18] = *(undefined2 *)(cVar4 * 2 + -0x7fcd7960);
      *(char *)(puVar3 + 0x15) = (char)((uint)(*psVar1 + iVar7 + 0x8000) >> 8);
      *(undefined *)(puVar3 + 0x19) = 1;
      FUN_80017ae4(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff,
                   0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      cVar4 = cVar4 + '\x01';
      if ('\a' < cVar4) {
        cVar4 = '\0';
      }
      iVar7 = iVar7 + 0x2000;
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: sc_totempuzzle_processAnimEvents
 * EN v1.0 Address: 0x801DD938
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801DE210
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 sc_totempuzzle_processAnimEvents(int param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24;
  int local_20;
  int local_1c [3];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  animUpdate->sequenceEventActive = 0;
  iVar4 = 0;
  do {
    if ((int)(uint)animUpdate->eventCount <= iVar4) {
      return 0;
    }
    bVar1 = animUpdate->eventIds[iVar4];
    if (bVar1 == 2) {
      iVar2 = FUN_80017b00(&local_20,local_1c);
      piVar3 = (int *)(iVar2 + local_20 * 4);
      for (; local_20 < local_1c[0]; local_20 = local_20 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == SC_TOTEMPUZZLE_PEER_OBJECT_TYPE)) {
          iVar2 = *(int *)(iVar2 + local_20 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,2);
          break;
        }
        piVar3 = piVar3 + 1;
      }
      *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 0x10;
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 1;
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x44,1,0,0);
      }
    }
    else if (bVar1 < 4) {
      iVar2 = FUN_80017b00(&local_28,&local_24);
      piVar3 = (int *)(iVar2 + local_28 * 4);
      for (; local_28 < local_24; local_28 = local_28 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == SC_TOTEMPUZZLE_PEER_OBJECT_TYPE)) {
          iVar2 = *(int *)(iVar2 + local_28 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,1);
          break;
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = iVar4 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_801ddb0c
 * EN v1.0 Address: 0x801DDB0C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801DE3F4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ddb0c(void)
{
  FUN_800067c0((int *)0xf0,0);
  FUN_8011eb10(0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ddb3c
 * EN v1.0 Address: 0x801DDB3C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DE424
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ddb3c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void sc_totempuzzle_release(void) {}
void sc_totempuzzle_initialise(void) {}

extern s16 lbl_80327A18[];
extern f32 lbl_803E55FC;
extern f32 lbl_803E562C;
extern f32 lbl_803E5630;
extern void fn_801DD170(int obj);
extern void *objFindTexture(int obj, int a, int b);
extern uint GameBit_Get(int eventId);
extern int randomGetRange(int lo, int hi);

#pragma peephole off
#pragma scheduling off
void sc_totempuzzle_init(u8* obj, u8* params) {
    u8* sub;
    int *tex;
    int r;
    f32 fz;

    sub = *(u8**)(obj + 0xb8);
    *(s8*)(obj + 0xad) = (s8)params[0x1b];
    if ((s8)obj[0xad] < 0 || (s8)obj[0xad] > 5) {
        obj[0xad] = 0;
    }
    if ((s8)obj[0xad] == 5) {
        tex = (int*)objFindTexture((int)obj, 0, 0);
        if (tex != NULL) {
            *tex = 0x100;
        }
    }
    *(s16*)(sub + 0x10) = (s16)(s8)obj[0xad];
    if (GameBit_Get(0x639) == 0) {
        *(f32*)(sub + 0xc) = (f32)(s32)lbl_80327A18[*(s16*)(sub + 0x10)];
    } else {
        *(f32*)(sub + 0xc) = lbl_803E562C;
        tex = (int*)objFindTexture((int)obj, 0, 0);
        if (tex != NULL) {
            *tex = 0x100;
        }
    }
    *(s16*)obj = (s16)(s32)*(f32*)(sub + 0xc);
    r = randomGetRange(7, 10);
    fz = (f32)r * lbl_803E5630;
    *(f32*)(sub + 4) = fz;
    *(f32*)sub = fz;
    if (((s8)obj[0xad]) & 1) {
        *(s16*)(sub + 0x12) = 1;
    }
    *(f32*)(sub + 8) = lbl_803E55FC;
    *(void**)(obj + 0xbc) = (void*)&fn_801DD170;
    *(u16*)(obj + 0xb0) = (u16)(*(u16*)(obj + 0xb0) | 0x6000);
}
#pragma scheduling reset
#pragma peephole reset
void sc_totembond_hitDetect(void) {}
void sc_totembond_release(void) {}
void sc_totembond_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_totembond_getExtraSize(void) { return 0x28; }
int sc_totembond_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5650;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void sc_totembond_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5650); }
#pragma peephole reset

extern void Music_Trigger(int track, int param);
extern void fn_8011F6D4(int p);
#pragma scheduling off
void sc_totembond_free(int obj) {
    Music_Trigger(240, 0);
    fn_8011F6D4(0);
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sc_totembond_init(int obj, int p2) {
    int *state;
    u32 v;
    s16 hi = (s16)(u16)((s32)*(s16 *)obj / 8192);
    state = *(int **)((char *)obj + 0xB8);
    *(s16 *)((char *)state + 0x24) = hi;
    *(void (**)(void))((char *)obj + 0xBC) = (void (*)(void))sc_totempuzzle_processAnimEvents;
    v = (u32)*(u16 *)((char *)obj + 0xB0) | 0x6000;
    *(u16 *)((char *)obj + 0xB0) = (u16)v;
}
#pragma peephole reset
#pragma scheduling reset
